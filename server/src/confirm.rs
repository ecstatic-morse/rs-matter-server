//! Confirming what a command did.
//!
//! Clients build their view of a device from `attribute_updated` events, so
//! after a command they need to hear its effect. A subscribed device reports
//! that itself, normally within a fraction of a second. Reading the endpoint
//! back as well, as `device_command` once did on every call, races those
//! reports: the read can be answered with the state from before the command
//! took effect and land after the report, and the stale value then sticks,
//! because to the device nothing has changed since and it never reports again.
//! (A light turned off showed as on a few seconds later, once the client
//! stopped showing what it had asked for.)
//!
//! Not reading back has the opposite failure. A subscription can die without
//! a word (the device rebooted, a Thread route broke, this server restarted
//! while the device held the old one) and it is only noticed as silent after
//! twice its max interval, which is ten minutes or more. Commands still
//! succeed on a fresh session the whole time, but no report says so.
//!
//! So a command is confirmed off the request path, after a pause:
//!
//! * The node reported since the command was sent: the subscription is
//!   working and has said what happened. Nothing to do.
//! * It did not: read the endpoint and publish what changed. If the read
//!   finds a change the subscription should have reported, the subscription
//!   is forgotten, and the monitor re-subscribes on its next pass instead of
//!   ten minutes later.
//! * A node with no subscription at all is read at once, as it always was.
//!
//! The pause is not on the request: requests on a connection are served one
//! at a time, so waiting there would hold up every command after this one.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::api::interaction::publish_attribute_changes;
use crate::api::{CallContext, ServerContext};
use crate::protocol::error::ApiError;
use crate::protocol::model::AttributesData;
use crate::protocol::paths::parse_path;

/// How long a subscribed node has to report a command's effect before it is
/// read back. Reports with a zero floor arrive within a second over Thread
/// even with a retransmission or two; a fade reports its level as it goes.
pub const REPORT_WITHIN: Duration = Duration::from_secs(2);

/// Endpoints waiting to be confirmed.
///
/// One entry per endpoint, for the newest command sent to it: a burst of
/// commands (a slider being dragged) is confirmed once, after the last.
#[derive(Default)]
pub struct Queue {
    pending: Mutex<BTreeMap<(u64, u16), Due>>,
    wake: Condvar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Due {
    /// When the command was sent.
    sent: Instant,
    /// When to look.
    at: Instant,
}

/// One endpoint to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub node_id: u64,
    pub endpoint: u16,
    /// When the newest command to the endpoint was sent.
    pub sent: Instant,
}

impl Queue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask for `endpoint` of `node_id` to be confirmed `after` the command
    /// sent at `sent`. A newer request replaces an older one.
    pub fn request(&self, node_id: u64, endpoint: u16, sent: Instant, after: Duration) {
        let due = Due {
            sent,
            at: sent + after,
        };
        let mut pending = self.pending.lock().unwrap();
        let entry = pending.entry((node_id, endpoint)).or_insert(due);
        if due.sent >= entry.sent {
            *entry = due;
        }
        drop(pending);
        self.wake.notify_one();
    }

    /// Wait until at least one confirmation is due, and take every one that is.
    pub fn take_due(&self) -> Vec<Confirmation> {
        let mut pending = self.pending.lock().unwrap();
        loop {
            let now = Instant::now();
            let due: Vec<_> = pending
                .iter()
                .filter(|(_, due)| due.at <= now)
                .map(|(&(node_id, endpoint), due)| Confirmation {
                    node_id,
                    endpoint,
                    sent: due.sent,
                })
                .collect();
            if !due.is_empty() {
                for c in &due {
                    pending.remove(&(c.node_id, c.endpoint));
                }
                return due;
            }
            pending = match pending.values().map(|due| due.at).min() {
                Some(next) => self.wake.wait_timeout(pending, next - now).unwrap().0,
                None => self.wake.wait(pending).unwrap(),
            };
        }
    }
}

/// What confirming a command came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The node reported after the command; its report stands.
    Reported,
    /// The node reported while it was being read; that report stands over
    /// the read, which may be older.
    ReportedDuringRead,
    /// The read found what the cache already held.
    Unchanged,
    /// The read found a change nobody had reported, and published it.
    /// `resubscribe`: the node was subscribed, so its subscription is broken.
    Corrected { resubscribe: bool },
    /// The read failed; the cache is left as it is.
    Unread,
}

/// Confirm one command, reading the endpoint with `read` if it comes to that.
pub async fn confirm<F, Fut>(context: &ServerContext, c: Confirmation, read: F) -> Outcome
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<AttributesData, ApiError>>,
{
    let subscriptions = &context.subscriptions;
    if subscriptions.reported_since(c.node_id, c.sent) {
        return Outcome::Reported;
    }
    let subscribed = subscriptions.holds(c.node_id);
    let reading = Instant::now();
    let attributes = match read().await {
        Ok(attributes) => attributes,
        Err(error) => {
            log::debug!(
                "Could not read endpoint {} of node {} back after a command: {}",
                c.endpoint,
                c.node_id,
                error
            );
            return Outcome::Unread;
        }
    };
    if subscriptions.reported_since(c.node_id, reading) {
        return Outcome::ReportedDuringRead;
    }
    let call = CallContext {
        server: context,
        connection_id: 0,
        message_id: &serde_json::Value::Null,
        peer: "",
    };
    if !publish_attribute_changes(call, c.node_id, &attributes) {
        return Outcome::Unchanged;
    }
    if subscribed {
        log::info!(
            "Node {} did not report what a command to endpoint {} changed; will re-subscribe",
            c.node_id,
            c.endpoint
        );
        subscriptions.forget(c.node_id);
    }
    Outcome::Corrected {
        resubscribe: subscribed,
    }
}

/// Confirm commands forever. Blocks; run it on a thread of its own.
pub fn run(context: Arc<ServerContext>) {
    loop {
        for c in context.confirmations.take_due() {
            // The whole endpoint is read because commands routinely change
            // another cluster: `moveToLevelWithOnOff` moves LevelControl *and*
            // OnOff.
            let Ok(path) = parse_path(&format!("{}/*/*", c.endpoint)) else {
                continue;
            };
            futures_lite::future::block_on(confirm(&context, c, || {
                context
                    .matter
                    .read_attributes(c.node_id, vec![path.to_attr_path()], false)
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests_support::test_context;
    use crate::protocol::model::MatterNodeData;
    use crate::storage::StoredNode;
    use futures_lite::future::block_on;
    use serde_json::json;

    fn context_with_light_on() -> ServerContext {
        let context = test_context();
        context.nodes.upsert(StoredNode::new(MatterNodeData::new(
            1,
            "2026-01-01T00:00:00.000Z".into(),
        )));
        context.nodes.set_attribute(1, "1/6/0", json!(true));
        context
    }

    fn reads_off() -> Result<AttributesData, ApiError> {
        Ok(AttributesData::from([("1/6/0".to_string(), json!(false))]))
    }

    fn command(sent: Instant) -> Confirmation {
        Confirmation {
            node_id: 1,
            endpoint: 1,
            sent,
        }
    }

    #[test]
    fn a_report_after_the_command_is_not_read_over() {
        let context = context_with_light_on();
        context
            .subscriptions
            .established(1, 7, Duration::from_secs(300));
        let sent = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        context.subscriptions.note_report(1);

        let outcome = block_on(confirm(&context, command(sent), || async {
            panic!("a reported command must not be read back")
        }));
        assert_eq!(outcome, Outcome::Reported);
        assert_eq!(
            context.nodes.get(1).unwrap().attributes["1/6/0"],
            json!(true)
        );
    }

    #[test]
    fn a_silent_subscription_is_read_back_corrected_and_dropped() {
        let context = context_with_light_on();
        context
            .subscriptions
            .established(1, 7, Duration::from_secs(300));
        std::thread::sleep(Duration::from_millis(2));
        let sent = Instant::now();
        let events = context.events.subscribe();

        let outcome = block_on(confirm(&context, command(sent), || async { reads_off() }));
        assert_eq!(outcome, Outcome::Corrected { resubscribe: true });
        assert_eq!(
            context.nodes.get(1).unwrap().attributes["1/6/0"],
            json!(false)
        );
        assert_eq!(
            events.try_recv().unwrap().payload["data"],
            json!([1, "1/6/0", false])
        );
        assert!(!context.subscriptions.holds(1));
    }

    #[test]
    fn a_report_during_the_read_wins_over_it() {
        let context = context_with_light_on();
        context
            .subscriptions
            .established(1, 7, Duration::from_secs(300));
        std::thread::sleep(Duration::from_millis(2));
        let sent = Instant::now();

        let outcome = block_on(confirm(&context, command(sent), || async {
            std::thread::sleep(Duration::from_millis(2));
            context.subscriptions.note_report(1);
            reads_off()
        }));
        assert_eq!(outcome, Outcome::ReportedDuringRead);
        assert_eq!(
            context.nodes.get(1).unwrap().attributes["1/6/0"],
            json!(true)
        );
        assert!(context.subscriptions.holds(1));
    }

    #[test]
    fn a_read_that_finds_nothing_new_keeps_the_subscription() {
        let context = context_with_light_on();
        context
            .subscriptions
            .established(1, 7, Duration::from_secs(300));
        std::thread::sleep(Duration::from_millis(2));
        let sent = Instant::now();

        let outcome = block_on(confirm(&context, command(sent), || async {
            Ok(AttributesData::from([("1/6/0".to_string(), json!(true))]))
        }));
        assert_eq!(outcome, Outcome::Unchanged);
        assert!(context.subscriptions.holds(1));
    }

    #[test]
    fn an_unsubscribed_node_is_corrected_without_resubscribing() {
        let context = context_with_light_on();
        let outcome = block_on(confirm(&context, command(Instant::now()), || async {
            reads_off()
        }));
        assert_eq!(outcome, Outcome::Corrected { resubscribe: false });
    }

    #[test]
    fn the_queue_confirms_the_newest_command_once_it_is_due() {
        let queue = Queue::new();
        let first = Instant::now();
        queue.request(1, 1, first, Duration::from_millis(30));
        let second = first + Duration::from_millis(10);
        queue.request(1, 1, second, Duration::from_millis(30));
        // An older command arriving late does not pull the confirmation back.
        queue.request(1, 1, first, Duration::from_millis(30));
        queue.request(2, 1, first, Duration::ZERO);

        assert_eq!(
            queue.take_due(),
            vec![Confirmation {
                node_id: 2,
                endpoint: 1,
                sent: first
            }]
        );
        let due = queue.take_due();
        assert!(Instant::now() >= second + Duration::from_millis(30));
        assert_eq!(
            due,
            vec![Confirmation {
                node_id: 1,
                endpoint: 1,
                sent: second
            }]
        );
    }
}
