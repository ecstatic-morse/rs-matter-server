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
///
/// rs-matter's `as_asn1` yields only the `TBSCertificate` (what the signature
/// covers), so this wraps it into the full `Certificate`:
/// `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`.
pub fn tlv_cert_to_der(tlv: &[u8]) -> Result<Vec<u8>, ApiError> {
    use rs_matter::cert::{CertRef, MAX_CERT_ASN1_LEN};
    use rs_matter::tlv::TLVElement;

    /// Matter TLV certificate tag for the raw `r || s` signature.
    const TAG_SIGNATURE: u8 = 11;
    /// `AlgorithmIdentifier { ecdsa-with-SHA256 }`, no parameters. `as_asn1`
    /// fails for any other algorithm, so the TBS always declares this one.
    const ECDSA_WITH_SHA256: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];

    let err = |what: &str, e: rs_matter::error::Error| {
        ApiError::sdk(format!(
            "Could not encode a certificate as DER ({what}): {:?}",
            e.code()
        ))
    };

    let mut tbs = vec![0u8; MAX_CERT_ASN1_LEN];
    let len = CertRef::new(TLVElement::new(tlv))
        .as_asn1(&mut tbs)
        .map_err(|e| err("TBS", e))?;
    tbs.truncate(len);

    let raw_sig = TLVElement::new(tlv)
        .structure()
        .and_then(|s| s.find_ctx(TAG_SIGNATURE))
        .and_then(|e| e.str())
        .map_err(|e| err("signature", e))?;
    if raw_sig.len() != 64 {
        return Err(ApiError::sdk(format!(
            "Could not encode a certificate as DER: {}-byte signature, expected 64",
            raw_sig.len()
        )));
    }
    let (r, s) = raw_sig.split_at(32);

    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    let sig_value = der_tlv(0x30, &[der_uint(r), der_uint(s)].concat());
    // signatureValue BIT STRING, no unused bits.
    let sig_bits = der_tlv(0x03, &[&[0u8][..], &sig_value].concat());

    Ok(der_tlv(
        0x30,
        &[&tbs[..], ECDSA_WITH_SHA256, &sig_bits].concat(),
    ))
}

/// One DER element: tag, definite length, contents.
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(contents);
    out
}

/// A DER INTEGER from unsigned big-endian bytes: minimal, and non-negative.
fn der_uint(be: &[u8]) -> Vec<u8> {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let digits = &be[first..];
    let mut contents = Vec::with_capacity(digits.len() + 1);
    if digits[0] & 0x80 != 0 {
        contents.push(0);
    }
    contents.extend_from_slice(digits);
    der_tlv(0x02, &contents)
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

    /// A self-signed root from rs-matter's own cert tests (`RCA1_SUCCESS`).
    const RCAC_TLV: &[u8] = &[
        0x15, 0x30, 0x1, 0x1, 0x0, 0x24, 0x2, 0x1, 0x37, 0x3, 0x24, 0x14, 0x0, 0x24, 0x15, 0x1,
        0x18, 0x26, 0x4, 0x80, 0x22, 0x81, 0x27, 0x26, 0x5, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x6,
        0x24, 0x14, 0x0, 0x24, 0x15, 0x1, 0x18, 0x24, 0x7, 0x1, 0x24, 0x8, 0x1, 0x30, 0x9, 0x41,
        0x4, 0x6d, 0x70, 0x7e, 0x4b, 0x98, 0xf6, 0x2b, 0xab, 0x44, 0xd6, 0xfe, 0xa3, 0x2e, 0x39,
        0xd8, 0xc3, 0x0, 0xa0, 0xe, 0xa8, 0x6c, 0x83, 0xff, 0x69, 0xd, 0xe8, 0x42, 0x1, 0xeb, 0xd,
        0xaa, 0x68, 0x5d, 0xcb, 0x97, 0x2, 0x80, 0x1d, 0xa8, 0x50, 0x2, 0x2e, 0x5a, 0xa2, 0x5a,
        0x2e, 0x51, 0x26, 0x4, 0xd2, 0x39, 0x62, 0xcd, 0x82, 0x38, 0x63, 0x28, 0xbf, 0x15, 0x1c,
        0xa6, 0x27, 0xe0, 0xd7, 0x37, 0xa, 0x35, 0x1, 0x29, 0x1, 0x18, 0x24, 0x2, 0x60, 0x30, 0x4,
        0x14, 0xd4, 0x56, 0x93, 0xbe, 0x70, 0x79, 0xf4, 0x9c, 0x70, 0x6b, 0x7, 0x6f, 0x11, 0x1c,
        0x6d, 0xe5, 0x64, 0xa4, 0x44, 0x74, 0x30, 0x5, 0x14, 0xd4, 0x56, 0x93, 0xbe, 0x70, 0x79,
        0xf4, 0x9c, 0x70, 0x6b, 0x7, 0x6f, 0x11, 0x1c, 0x6d, 0xe5, 0x64, 0xa4, 0x44, 0x74, 0x18,
        0x30, 0xb, 0x40, 0x3, 0xd, 0x77, 0xe1, 0x9e, 0xea, 0x9c, 0x5, 0x5c, 0xcc, 0x47, 0xe8, 0xb3,
        0x18, 0x1a, 0xd1, 0x74, 0xee, 0xc6, 0x2e, 0xa1, 0x20, 0x16, 0xbd, 0x20, 0xb4, 0x3d, 0xac,
        0x24, 0xbe, 0x17, 0xf9, 0xe, 0xb7, 0x9a, 0x98, 0xc8, 0xbc, 0x6a, 0xce, 0x99, 0x2a, 0x2e,
        0x63, 0x4c, 0x76, 0x6, 0x45, 0x93, 0xd3, 0x7c, 0x4, 0x0, 0xe4, 0xc7, 0x78, 0xe9, 0x83,
        0x5b, 0xc, 0x33, 0x61, 0x5c, 0x2e, 0x18,
    ];

    #[test]
    fn der_certificates_are_complete_and_their_signatures_verify() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use x509_cert::der::{Decode, Encode};

        let der = tlv_cert_to_der(RCAC_TLV).unwrap();
        // A full Certificate, not just its TBSCertificate (what the CHIP SDK
        // rejected with ASN1_ERROR_INVALID_ENCODING), with nothing trailing.
        let cert = x509_cert::Certificate::from_der(&der).unwrap();

        let tbs = cert.tbs_certificate().to_der().unwrap();
        let key = VerifyingKey::from_sec1_bytes(
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
        let sig = Signature::from_der(cert.signature().raw_bytes()).unwrap();
        key.verify(&tbs, &sig).expect("self-signature verifies");
    }

    #[test]
    fn der_integers_are_minimal_and_non_negative() {
        assert_eq!(der_uint(&[0, 0, 0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(der_uint(&[0, 0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der_uint(&[0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(der_tlv(0x30, &[0; 200])[..3], [0x30, 0x81, 200]);
    }
}
