//! Server-to-client events.
//!
//! Two things matter for parity: the exact `{event, data}` shape, and *who*
//! receives each event. Older clients never subscribed to the Thread, topology
//! or WebRTC events, so those are gated behind an opt-in the client performs by
//! issuing the corresponding command — a connection that never asks never
//! receives them.

use std::fmt;
use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Value};

use super::model::{MatterNodeData, MatterNodeEvent, NetworkTopology, ServerInfo};

/// Which connections an event may be delivered to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventClass {
    /// Delivered to every connection that issued `start_listening`.
    Always,
    /// Requires the connection to have issued a Thread command.
    ThreadDiagnostics,
    /// Requires the connection to have issued `get_network_topology`.
    NetworkTopology,
    /// Requires the connection to have issued a WebRTC command.
    WebRtc,
    /// Delivered only to the connection with this id, whether or not it
    /// issued `start_listening`. Progress for a command belongs to whoever
    /// sent it; every other client would only see noise.
    Requester(u64),
}

/// An event plus its delivery class.
#[derive(Clone, Debug)]
pub struct Event {
    pub class: EventClass,
    pub payload: Value,
}

impl Event {
    fn new(class: EventClass, name: &str, data: Value) -> Self {
        Self {
            class,
            payload: json!({ "event": name, "data": data }),
        }
    }

    fn always(name: &str, data: Value) -> Self {
        Self::new(EventClass::Always, name, data)
    }

    pub fn name(&self) -> &str {
        self.payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn node_added(node: &MatterNodeData) -> Self {
        Self::always("node_added", to_value(node))
    }

    pub fn node_updated(node: &MatterNodeData) -> Self {
        Self::always("node_updated", to_value(node))
    }

    pub fn node_removed(node_id: u64) -> Self {
        Self::always("node_removed", json!(node_id))
    }

    pub fn node_event(event: &MatterNodeEvent) -> Self {
        Self::always("node_event", to_value(event))
    }

    /// `[node_id, "endpoint/cluster/attribute", value]`.
    pub fn attribute_updated(node_id: u64, path: &str, value: Value) -> Self {
        Self::always("attribute_updated", json!([node_id, path, value]))
    }

    pub fn endpoint_added(node_id: u64, endpoint_id: u16) -> Self {
        Self::always(
            "endpoint_added",
            json!({ "node_id": node_id, "endpoint_id": endpoint_id }),
        )
    }

    pub fn endpoint_removed(node_id: u64, endpoint_id: u16) -> Self {
        Self::always(
            "endpoint_removed",
            json!({ "node_id": node_id, "endpoint_id": endpoint_id }),
        )
    }

    pub fn server_info_updated(info: &ServerInfo) -> Self {
        Self::always("server_info_updated", to_value(info))
    }

    pub fn server_shutdown() -> Self {
        Self::always("server_shutdown", json!({}))
    }

    pub fn thread_diagnostics_updated(batch: Value) -> Self {
        Self::new(
            EventClass::ThreadDiagnostics,
            "thread_diagnostics_updated",
            batch,
        )
    }

    pub fn network_topology_updated(topology: &NetworkTopology) -> Self {
        Self::new(
            EventClass::NetworkTopology,
            "network_topology_updated",
            to_value(topology),
        )
    }

    pub fn webrtc_callback(data: Value) -> Self {
        Self::new(EventClass::WebRtc, "webrtc_callback", data)
    }

    /// One step of a commissioning command, for the connection that sent it.
    ///
    /// Not part of the matterjs-server protocol, so it is only produced when
    /// the request asks for it with `"progress": true`.
    pub fn commissioning_progress(
        connection_id: u64,
        message_id: &Value,
        step: CommissioningStep,
        node_id: Option<u64>,
    ) -> Self {
        let mut data = json!({ "message_id": message_id, "step": step });
        if let Some(node_id) = node_id {
            data["node_id"] = json!(node_id);
        }
        Self::new(
            EventClass::Requester(connection_id),
            "commissioning_progress",
            data,
        )
    }
}

/// The steps a commissioning command reports, in the order they happen.
///
/// Each is announced as it *starts*, so a client showing the latest one shows
/// what is being waited on. The command's own response, success or error, is
/// what says the flow ended. Not every flow passes through every step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissioningStep {
    /// Browsing mDNS for a commissionable device matching the pairing code.
    Discovering,
    /// Scanning for the device's Bluetooth advertisement.
    BluetoothScanning,
    /// PASE, attestation, CSR and AddNOC: one opaque call into rs-matter.
    InstallingCredentials,
    /// Handing a Bluetooth-commissioned device its Wi-Fi or Thread network.
    ProvisioningNetwork,
    /// Waiting for the device to announce itself on its operational network.
    OperationalDiscovery,
    /// CASE and `CommissioningComplete`, with rs-matter's own retries.
    Completing,
    /// Registering this controller as the device's check-in client.
    IcdRegistration,
    /// Telling the device what to call this fabric.
    FabricLabel,
    /// Reading the device's attributes for the first time.
    Interview,
}

/// Where a commissioning flow reports its steps.
///
/// Cheap to clone and `Send`, because the flow runs partly in the protocol
/// layer and partly on the Matter actor's thread. A disabled reporter, which
/// is what every request gets unless it asks for progress, does nothing.
#[derive(Clone, Default)]
pub struct Progress {
    target: Option<ProgressTarget>,
}

#[derive(Clone)]
struct ProgressTarget {
    connection_id: u64,
    message_id: Value,
    sink: Arc<dyn Fn(Event) + Send + Sync>,
}

impl Progress {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn new(
        connection_id: u64,
        message_id: Value,
        sink: Arc<dyn Fn(Event) + Send + Sync>,
    ) -> Self {
        Self {
            target: Some(ProgressTarget {
                connection_id,
                message_id,
                sink,
            }),
        }
    }

    pub fn step(&self, step: CommissioningStep) {
        self.emit(step, None);
    }

    pub fn node_step(&self, step: CommissioningStep, node_id: u64) {
        self.emit(step, Some(node_id));
    }

    fn emit(&self, step: CommissioningStep, node_id: Option<u64>) {
        if let Some(target) = &self.target {
            (target.sink)(Event::commissioning_progress(
                target.connection_id,
                &target.message_id,
                step,
                node_id,
            ));
        }
    }
}

impl fmt::Debug for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            Some(target) => write!(f, "Progress(message {})", target.message_id),
            None => f.write_str("Progress(disabled)"),
        }
    }
}

/// Wire models are infallible to serialize; a failure here would mean a model
/// with a non-string map key, which the type system already rules out.
fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// What a connection has opted into. `start_listening` turns on the base
/// stream; the opt-in flags are latched by issuing the matching command, and
/// (like the reference) latch even when that command returns an error, because
/// issuing it is what proves the client understands the event.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventSubscriptions {
    /// The connection these subscriptions belong to, which is what
    /// [`EventClass::Requester`] events are addressed to.
    pub connection_id: u64,
    pub listening: bool,
    pub thread_diagnostics: bool,
    pub network_topology: bool,
    pub webrtc: bool,
}

impl EventSubscriptions {
    pub fn for_connection(connection_id: u64) -> Self {
        Self {
            connection_id,
            ..Self::default()
        }
    }

    /// Latch the opt-ins implied by a command name.
    pub fn observe_command(&mut self, command: &str) {
        match command {
            "start_listening" => self.listening = true,
            "get_thread_diagnostics" | "get_thread_border_routers" => {
                self.thread_diagnostics = true
            }
            "get_network_topology" => self.network_topology = true,
            "send_webrtc_provider_command" => self.webrtc = true,
            _ => {}
        }
    }

    pub fn accepts(&self, event: &Event) -> bool {
        if let EventClass::Requester(connection_id) = event.class {
            return connection_id == self.connection_id;
        }
        if !self.listening {
            return false;
        }
        match event.class {
            EventClass::Requester(_) => unreachable!("handled above"),
            EventClass::Always => true,
            EventClass::ThreadDiagnostics => self.thread_diagnostics,
            EventClass::NetworkTopology => self.network_topology,
            EventClass::WebRtc => self.webrtc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_updated_is_a_positional_triple() {
        let event = Event::attribute_updated(1, "1/6/0", json!(true));
        assert_eq!(event.payload["event"], json!("attribute_updated"));
        assert_eq!(event.payload["data"], json!([1, "1/6/0", true]));
    }

    #[test]
    fn node_removed_carries_a_bare_node_id() {
        assert_eq!(Event::node_removed(4).payload["data"], json!(4));
    }

    #[test]
    fn nothing_is_delivered_before_start_listening() {
        let subscriptions = EventSubscriptions::default();
        assert!(!subscriptions.accepts(&Event::node_removed(1)));
    }

    #[test]
    fn opt_in_events_need_their_command_first() {
        let mut subscriptions = EventSubscriptions::default();
        subscriptions.observe_command("start_listening");
        let topology = Event::network_topology_updated(&NetworkTopology::default());
        assert!(subscriptions.accepts(&Event::node_removed(1)));
        assert!(!subscriptions.accepts(&topology));

        subscriptions.observe_command("get_network_topology");
        assert!(subscriptions.accepts(&topology));
        assert!(!subscriptions.accepts(&Event::thread_diagnostics_updated(json!({}))));
    }

    #[test]
    fn progress_reaches_only_the_requesting_connection() {
        let event = Event::commissioning_progress(
            7,
            &json!("42"),
            CommissioningStep::OperationalDiscovery,
            Some(3),
        );
        assert_eq!(event.payload["event"], json!("commissioning_progress"));
        assert_eq!(
            event.payload["data"],
            json!({"message_id": "42", "step": "operational_discovery", "node_id": 3})
        );

        // The requester gets it without having issued `start_listening`.
        assert!(EventSubscriptions::for_connection(7).accepts(&event));

        let mut other = EventSubscriptions::for_connection(8);
        other.observe_command("start_listening");
        assert!(!other.accepts(&event));
    }

    #[test]
    fn a_disabled_reporter_emits_nothing_and_an_enabled_one_tags_its_request() {
        use std::sync::Mutex;

        Progress::disabled().step(CommissioningStep::Discovering);

        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let seen = seen.clone();
            Arc::new(move |event: Event| seen.lock().unwrap().push(event.payload))
        };
        let progress = Progress::new(1, json!(9), sink);
        progress.step(CommissioningStep::Discovering);
        progress.node_step(CommissioningStep::Interview, 5);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0]["data"],
            json!({"message_id": 9, "step": "discovering"})
        );
        assert_eq!(seen[1]["data"]["node_id"], json!(5));
    }

    #[test]
    fn thread_opt_in_covers_both_thread_commands() {
        let mut subscriptions = EventSubscriptions::default();
        subscriptions.observe_command("start_listening");
        subscriptions.observe_command("get_thread_border_routers");
        assert!(subscriptions.accepts(&Event::thread_diagnostics_updated(json!({}))));
    }
}
