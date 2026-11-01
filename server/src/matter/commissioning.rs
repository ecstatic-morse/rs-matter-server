//! Pairing-code parsing and the commissioning flow.
//!
//! A pairing code carries two things the controller needs: the setup passcode,
//! and enough of the device's identity to find it on the network. rs-matter's
//! payload parsers produce both, including the discriminator filter — a QR code
//! carries the full 12-bit discriminator while a manual code carries only its
//! top 4 bits, and the filter records which, so discovery matches the same way
//! the reference does.

use std::num::NonZeroU8;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{CanonPkcSecretKey, Crypto};
use rs_matter::dm::clusters::decl::network_commissioning::{
    Feature, NetworkCommissioningClient, NetworkCommissioningStatusEnum,
};
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, CommissionResult, Commissioner};
use rs_matter::pairing::qr::QrPayload;
use rs_matter::tlv::OctetStr;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::mdns::CommissionableFilter;
use rs_matter::transport::network::Address;
use rs_matter::Matter;

use crate::protocol::error::ApiError;
use crate::protocol::events::{CommissioningStep, Progress};

/// What a pairing code resolves to.
#[derive(Clone, Debug)]
pub struct PairingInfo {
    pub passcode: u32,
    /// Discovery filter matching this device: a long discriminator from a QR
    /// code, a short one from a manual code.
    pub filter: CommissionableFilter,
}

/// Credentials for the network a device should be told to join.
///
/// Both kinds are carried rather than one, because which one applies is a
/// property of the device: a controller can hold Wi-Fi and Thread credentials
/// at once, and only the device's `NetworkCommissioning` feature map says
/// which it can use.
#[derive(Clone, Debug, Default)]
pub struct NetworkCredentials {
    pub wifi: Option<WifiCredentials>,
    pub thread: Option<ThreadCredentials>,
}

#[derive(Clone, Debug)]
pub struct WifiCredentials {
    pub ssid: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ThreadCredentials {
    /// The operational dataset, as raw MeshCoP TLV.
    pub dataset: Vec<u8>,
    /// The extended PAN id, which is how `ConnectNetwork` names a Thread
    /// network — the equivalent of an SSID.
    pub ext_pan_id: Vec<u8>,
}

impl NetworkCredentials {
    pub fn is_empty(&self) -> bool {
        self.wifi.is_none() && self.thread.is_none()
    }
}

/// What happens after AddNOC is accepted.
///
/// The two travel together because both answer the same question — how to
/// finish once the device holds its operational certificate — and splitting
/// them across separate parameters made the signature unreadable.
pub struct Completion<'a> {
    /// The network to hand the device, for one that does not have one yet.
    pub credentials: Option<&'a NetworkCredentials>,
    /// Where to report each step as it starts.
    pub progress: &'a Progress,
}

/// What a completed commissioning produced.
#[derive(Clone, Copy, Debug)]
pub struct CommissionOutcome {
    pub node_id: u64,
    /// The fabric slot the device assigned to us, needed to remove ourselves
    /// from it later.
    pub device_fabric_index: u8,
}

/// Parse a QR (`MT:`) or manual pairing code.
pub fn parse_pairing_code(code: &str) -> Result<PairingInfo, ApiError> {
    let code = code.trim();
    if code.is_empty() {
        return Err(ApiError::invalid_args("Missing code"));
    }

    if let Some(rest) = code.strip_prefix("MT:") {
        let _ = rest;
        let mut buf = [0u8; 256];
        let payload = QrPayload::parse(code, &mut buf).map_err(|e| {
            ApiError::invalid_args(format!("Invalid QR pairing code: {:?}", e.code()))
        })?;
        return Ok(PairingInfo {
            passcode: payload.passcode(),
            filter: payload.commissionable_filter(),
        });
    }

    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != code.chars().filter(|c| !matches!(c, '-' | ' ')).count() {
        return Err(ApiError::invalid_args(format!(
            "Unrecognized pairing code format: {}",
            code
        )));
    }

    let payload = QrPayload::parse_pairing_code(&digits).map_err(|e| {
        ApiError::invalid_args(format!("Invalid manual pairing code: {:?}", e.code()))
    })?;
    Ok(PairingInfo {
        passcode: payload.passcode(),
        filter: payload.commissionable_filter(),
    })
}

/// Run PASE, AddNOC, CASE and CommissioningComplete against a device at a
/// known address.
pub async fn commission_at_address<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    issuer_private_key: &CanonPkcSecretKey,
    peer_addr: Address,
    passcode: u32,
    node_id: u64,
    completion: Completion<'_>,
) -> Result<CommissionOutcome, ApiError> {
    let progress = completion.progress;
    let fab_idx: NonZeroU8 = matter
        .with_state(|state| state.fabrics.iter().next().map(|f| f.fab_idx()))
        .ok_or_else(|| ApiError::sdk("No fabric is installed on the controller"))?;

    // The NOC generator only caches certificate metadata, so it is rebuilt per
    // request; that keeps its scratch buffer on this stack frame instead of in
    // a self-referential long-lived structure, and the actor already
    // serializes the requests that use it.
    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = matter
        .with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            // Two shapes of fabric reach this line. One created here has an
            // ICAC and signs with the ICAC key; one imported from
            // matterjs-server usually has none and signs with the root key.
            // rs-matter picks the issuer from whether `icac` is empty, so both
            // work as long as the stored key is the one that matches.
            NocGenerator::create(
                issuer_private_key.reference(),
                fabric.root_ca(),
                fabric.icac(),
                &mut noc_buf,
            )
        })
        .map_err(|e| ApiError::sdk(format!("Failed to prepare NOC issuance: {:?}", e.code())))?;

    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    );
    let options = CommissionOptions {
        // rs-matter has no DCL-backed attestation verification yet, and
        // rejecting every device instead would make commissioning impossible.
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    progress.node_step(CommissioningStep::InstallingCredentials, node_id);
    let phase1 = commissioner
        .commission(peer_addr, passcode, &options, node_id, VALID_FOREVER)
        .await
        .map_err(|e| {
            ApiError::commission_failed(format!("Commissioning failed: {:?}", e.code()))
        })?;
    // A device reached over Bluetooth has no network yet, so it has to be
    // given one before phase 2 can reach it over IP at all. This sits between
    // AddNOC and CASE because the Matter spec puts it there: the fail-safe is
    // still armed and the PASE session is still the only way to talk.
    if let Some(credentials) = completion.credentials {
        progress.node_step(CommissioningStep::ProvisioningNetwork, node_id);
        provision_network(matter, crypto, peer_addr, passcode, credentials).await?;
    }

    progress.node_step(CommissioningStep::Completing, node_id);
    commissioner.complete_via_case(&phase1).await.map_err(|e| {
        ApiError::commission_failed(format!(
            "Commissioning could not be completed over CASE: {:?}",
            e.code()
        ))
    })?;

    Ok(CommissionOutcome {
        node_id: phase1.device_node_id,
        device_fabric_index: phase1.fabric_index.get(),
    })
}

/// What a fabric gives an outside commissioner to install on a device.
///
/// Remote-CA commissioning: another commissioner (a phone, typically) runs
/// PASE and sends the device's CSR here; the NOC chain, IPK and admin subject
/// below are what it then hands the device in `AddTrustedRootCertificate` and
/// `AddNOC`. The device ends up on this fabric without the other commissioner
/// ever holding an identity on it.
#[derive(Clone, Debug)]
pub struct IssuedCredentials {
    pub node_id: u64,
    pub noc: Vec<u8>,
    /// Empty for a fabric that signs directly off its root.
    pub icac: Vec<u8>,
    pub rcac: Vec<u8>,
    /// The same three certificates as X.509 DER. The CHIP SDK's commissioners
    /// (Android's `NOCChainIssuer`, Darwin's `MTROperationalCertificateIssuer`)
    /// take DER and convert to Matter TLV themselves.
    pub noc_der: Vec<u8>,
    pub icac_der: Vec<u8>,
    pub rcac_der: Vec<u8>,
    /// The IPK epoch key, as `AddNOC` carries it.
    pub ipk: Vec<u8>,
    /// `CaseAdminSubject`: this controller's node id, so the ACL entry the
    /// device creates on `AddNOC` names us as its administrator.
    pub admin_subject: u64,
    pub admin_vendor_id: u16,
}

/// Sign a device's CSR with this fabric's issuer, for a node id the caller
/// has already allocated.
///
/// Attestation is not checked here, and cannot be: it was verified (or not)
/// by whoever ran PASE. rs-matter has no attestation verification of its own
/// yet, so this is no weaker than `commission_with_code`.
pub fn issue_credentials<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    issuer_private_key: &CanonPkcSecretKey,
    csr_der: &[u8],
    node_id: u64,
) -> Result<IssuedCredentials, ApiError> {
    let fab_idx = controller_fabric(matter)?;

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = matter
        .with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            NocGenerator::create(
                issuer_private_key.reference(),
                fabric.root_ca(),
                fabric.icac(),
                &mut noc_buf,
            )
        })
        .map_err(|e| ApiError::sdk(format!("Failed to prepare NOC issuance: {:?}", e.code())))?;

    // `generate` also checks the CSR's self-signature, so a CSR that does not
    // prove possession of its key is refused before anything is signed.
    let noc = noc_generator
        .generate(crypto, csr_der, node_id, &[], VALID_FOREVER)
        .map_err(|e| ApiError::invalid_args(format!("Could not sign the CSR: {:?}", e.code())))?
        .to_vec();

    let mut issued = matter
        .with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            Ok::<_, rs_matter::error::Error>(IssuedCredentials {
                node_id,
                noc: noc.clone(),
                icac: fabric.icac().to_vec(),
                rcac: fabric.root_ca().to_vec(),
                noc_der: Vec::new(),
                icac_der: Vec::new(),
                rcac_der: Vec::new(),
                ipk: fabric.ipk().epoch_key().access().to_vec(),
                admin_subject: fabric.node_id(),
                admin_vendor_id: fabric.vendor_id(),
            })
        })
        .map_err(|e| ApiError::sdk(format!("Failed to read the fabric: {:?}", e.code())))?;

    issued.noc_der = tlv_cert_to_der(&issued.noc)?;
    issued.rcac_der = tlv_cert_to_der(&issued.rcac)?;
    if !issued.icac.is_empty() {
        issued.icac_der = tlv_cert_to_der(&issued.icac)?;
    }
    Ok(issued)
}

/// Re-encode a Matter TLV certificate as the X.509 DER it was derived from.
pub fn tlv_cert_to_der(tlv: &[u8]) -> Result<Vec<u8>, ApiError> {
    use rs_matter::cert::{CertRef, MAX_CERT_ASN1_LEN};
    use rs_matter::tlv::TLVElement;

    let mut der = vec![0u8; MAX_CERT_ASN1_LEN];
    let len = CertRef::new(TLVElement::new(tlv))
        .as_asn1(&mut der)
        .map_err(|e| {
            ApiError::sdk(format!(
                "Could not encode a certificate as DER: {:?}",
                e.code()
            ))
        })?;
    der.truncate(len);
    Ok(der)
}

/// Finish commissioning a device another commissioner installed our NOC on:
/// CASE to it as this fabric's administrator, then `CommissioningComplete`.
///
/// The device accepts that from any node on the fabric its fail-safe is
/// armed for, not only from whoever armed it. The fail-safe is the other
/// commissioner's; it has to have armed it for long enough to cover this.
pub async fn complete_commissioning<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    issuer_private_key: &CanonPkcSecretKey,
    node_id: u64,
) -> Result<(), ApiError> {
    let fab_idx = controller_fabric(matter)?;

    // `Commissioner` insists on a NOC generator although phase 2 never signs
    // anything; this one is built and dropped unused.
    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = matter
        .with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;
            NocGenerator::create(
                issuer_private_key.reference(),
                fabric.root_ca(),
                fabric.icac(),
                &mut noc_buf,
            )
        })
        .map_err(|e| {
            ApiError::sdk(format!(
                "Failed to prepare the commissioner: {:?}",
                e.code()
            ))
        })?;
    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    );

    // Phase 2 reads only the node id. The device-side fabric index is not
    // known here (the other commissioner got it in `NOCResponse`), and
    // nothing on this path uses it.
    let phase1 = CommissionResult {
        fabric_index: NonZeroU8::MIN,
        device_node_id: node_id,
    };
    commissioner.complete_via_case(&phase1).await.map_err(|e| {
        ApiError::commission_failed(format!(
            "Commissioning could not be completed over CASE: {:?}",
            e.code()
        ))
    })
}

fn controller_fabric(matter: &Matter<'_>) -> Result<NonZeroU8, ApiError> {
    matter
        .with_state(|state| state.fabrics.iter().next().map(|f| f.fab_idx()))
        .ok_or_else(|| ApiError::sdk("No fabric is installed on the controller"))
}

/// Hand a device its network credentials over the existing PASE session.
///
/// `Exchange::initiate_pase` reuses the PASE session the commissioner already
/// established with this peer — reuse is keyed by peer address — so each step
/// here is another exchange on that session rather than a second SPAKE2+
/// handshake. Each client view consumes its exchange, which is why there are
/// three of them: one IM transaction each.
async fn provision_network<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
    credentials: &NetworkCredentials,
) -> Result<(), ApiError> {
    // Which command the device accepts is a property of the device, not of
    // what happens to be stored here, so ask rather than assume. Getting it
    // wrong produces an obscure failure several steps later.
    let features = {
        let exchange = pase_exchange(matter, crypto, peer_addr, passcode).await?;
        let raw = exchange
            .network_commissioning()
            .feature_map_read(ROOT_ENDPOINT_ID)
            .await
            .map_err(|e| {
                ApiError::commission_failed(format!(
                    "Could not read the device's NetworkCommissioning features: {:?}",
                    e.code()
                ))
            })?;
        Feature::from_bits_truncate(raw)
    };

    // The device decides, not the store: a controller may hold both kinds.
    if features.contains(Feature::WI_FI_NETWORK_INTERFACE) {
        if let Some(wifi) = &credentials.wifi {
            let exchange = pase_exchange(matter, crypto, peer_addr, passcode).await?;
            let handle = exchange
                .network_commissioning()
                .add_or_update_wi_fi_network(ROOT_ENDPOINT_ID, |req| {
                    req.ssid(OctetStr::new(wifi.ssid.as_bytes()))?
                        .credentials(OctetStr::new(wifi.password.as_bytes()))?
                        .breadcrumb(Some(0))?
                        .end()
                })
                .await
                .map_err(|e| {
                    ApiError::commission_failed(format!(
                        "AddOrUpdateWiFiNetwork failed: {:?}",
                        e.code()
                    ))
                })?;
            check_network_status(
                handle
                    .response()
                    .ok()
                    .and_then(|r| r.networking_status().ok()),
                "AddOrUpdateWiFiNetwork",
            )?;
            let _ = handle.complete().await;

            return connect_network(matter, crypto, peer_addr, passcode, wifi.ssid.as_bytes())
                .await;
        }
    }

    if features.contains(Feature::THREAD_NETWORK_INTERFACE) {
        if let Some(thread) = &credentials.thread {
            let exchange = pase_exchange(matter, crypto, peer_addr, passcode).await?;
            let handle = exchange
                .network_commissioning()
                .add_or_update_thread_network(ROOT_ENDPOINT_ID, |req| {
                    req.operational_dataset(OctetStr::new(&thread.dataset))?
                        .breadcrumb(Some(0))?
                        .end()
                })
                .await
                .map_err(|e| {
                    ApiError::commission_failed(format!(
                        "AddOrUpdateThreadNetwork failed: {:?}",
                        e.code()
                    ))
                })?;
            check_network_status(
                handle
                    .response()
                    .ok()
                    .and_then(|r| r.networking_status().ok()),
                "AddOrUpdateThreadNetwork",
            )?;
            let _ = handle.complete().await;

            return connect_network(matter, crypto, peer_addr, passcode, &thread.ext_pan_id).await;
        }
    }

    // Ethernet devices need no provisioning: they are on a network the moment
    // they are plugged in, so an empty intersection is only a failure when the
    // device actually has a radio to configure.
    if features.contains(Feature::ETHERNET_NETWORK_INTERFACE)
        && !features
            .intersects(Feature::WI_FI_NETWORK_INTERFACE | Feature::THREAD_NETWORK_INTERFACE)
    {
        return Ok(());
    }

    Err(ApiError::commission_failed(format!(
        "No usable credentials for this device. It supports {:?}, and this server has {}. \
         Store matching credentials with `set_wifi_credentials` or `set_thread_dataset`.",
        features,
        match (&credentials.wifi, &credentials.thread) {
            (Some(_), Some(_)) => "both Wi-Fi and Thread",
            (Some(_), None) => "Wi-Fi only",
            (None, Some(_)) => "Thread only",
            (None, None) => "none",
        }
    )))
}

/// Tell the device to join the network it was just given.
///
/// The device drops its Bluetooth link and brings up its radio, so this is the
/// last thing that can be said over PASE.
async fn connect_network<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
    network_id: &[u8],
) -> Result<(), ApiError> {
    let exchange = pase_exchange(matter, crypto, peer_addr, passcode).await?;
    let handle = exchange
        .network_commissioning()
        .connect_network(ROOT_ENDPOINT_ID, |req| {
            req.network_id(OctetStr::new(network_id))?
                .breadcrumb(Some(0))?
                .end()
        })
        .await
        .map_err(|e| {
            ApiError::commission_failed(format!("ConnectNetwork failed: {:?}", e.code()))
        })?;
    check_network_status(
        handle
            .response()
            .ok()
            .and_then(|r| r.networking_status().ok()),
        "ConnectNetwork",
    )?;
    let _ = handle.complete().await;

    Ok(())
}

async fn pase_exchange<'a, C: Crypto>(
    matter: &'a Matter<'a>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
) -> Result<Exchange<'a>, ApiError> {
    Exchange::initiate_pase(matter, crypto, peer_addr, passcode)
        .await
        .map_err(|e| {
            ApiError::commission_failed(format!(
                "Could not open an exchange on the PASE session: {:?}",
                e.code()
            ))
        })
}

/// Turn a `NetworkCommissioningStatus` into something an operator can act on.
///
/// These are the failures a person actually hits — a mistyped password, an
/// SSID the device cannot see — so they are worth naming rather than
/// reporting as a generic commissioning failure.
fn check_network_status(
    status: Option<NetworkCommissioningStatusEnum>,
    command: &str,
) -> Result<(), ApiError> {
    let Some(status) = status else {
        return Err(ApiError::commission_failed(format!(
            "{command} returned a response that could not be decoded"
        )));
    };

    if status == NetworkCommissioningStatusEnum::Success {
        return Ok(());
    }

    let explanation = match status {
        NetworkCommissioningStatusEnum::AuthFailure => {
            "the credentials stored on this server were rejected"
        }
        NetworkCommissioningStatusEnum::NetworkNotFound => {
            "the device cannot see that network from where it is"
        }
        NetworkCommissioningStatusEnum::NetworkIDNotFound => {
            "the device has no network configured under that id"
        }
        NetworkCommissioningStatusEnum::UnsupportedSecurity => {
            "the network's security mode is not one the device supports"
        }
        NetworkCommissioningStatusEnum::RegulatoryError => {
            "the device rejected the network on regulatory grounds"
        }
        NetworkCommissioningStatusEnum::IPV6Failed => {
            "the device joined the network but could not bring up IPv6, which Matter needs"
        }
        NetworkCommissioningStatusEnum::OutOfRange
        | NetworkCommissioningStatusEnum::BoundsExceeded => {
            "the device rejected a value as out of range"
        }
        _ => "the device rejected it",
    };

    Err(ApiError::commission_failed(format!(
        "{command} was refused: {explanation} ({status:?})"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_manual_pairing_code_into_a_short_discriminator_filter() {
        // The canonical chip-tool test code for passcode 20202021 /
        // discriminator 3840.
        let info = parse_pairing_code("34970112332").unwrap();
        assert_eq!(info.passcode, 20202021);
        // A manual code only carries the top 4 bits of the discriminator, so
        // discovery has to browse the short-discriminator subtype.
        assert_eq!(info.filter.short_discriminator, Some(0x0F));
        assert_eq!(info.filter.discriminator, None);
    }

    #[test]
    fn accepts_manual_codes_with_separators() {
        let plain = parse_pairing_code("34970112332").unwrap();
        let spaced = parse_pairing_code("3497-011-2332").unwrap();
        assert_eq!(plain.passcode, spaced.passcode);
    }

    #[test]
    fn rejects_empty_and_malformed_codes() {
        assert_eq!(parse_pairing_code("").unwrap_err().code.as_i64(), 8);
        assert_eq!(parse_pairing_code("   ").unwrap_err().code.as_i64(), 8);
        assert!(parse_pairing_code("not-a-code").is_err());
        assert!(parse_pairing_code("MT:GARBAGE").is_err());
    }
}
