//! Attribute reads and writes, and command invocation.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::matter::clusters;
use crate::matter::tlv_json::{self, TlvNode};
use crate::protocol::error::{ApiError, ApiResult};
use crate::protocol::events::Event;
use crate::protocol::message::Args;
use crate::protocol::model::AttributesData;
use crate::protocol::paths::{format_path, parse_path_arg, parse_write_path};

use super::{require_node, CallContext};

/// Merge freshly read attributes into the cached node and announce what
/// changed.
///
/// Every path that reaches a client as an `attribute_updated` event goes
/// through here, so a value can never be announced without also being cached —
/// which is what stops a client and the controller disagreeing about state.
pub fn publish_attribute_changes(
    context: CallContext<'_>,
    node_id: u64,
    attributes: &AttributesData,
) -> bool {
    let mut changed = false;
    for (path, value) in attributes {
        if context
            .server
            .nodes
            .set_attribute(node_id, path, value.clone())
            .is_some()
        {
            changed = true;
            context
                .server
                .events
                .publish(Event::attribute_updated(node_id, path, value.clone()));
        }
    }
    if changed {
        context.server.nodes.save_soon();
    }
    changed
}

pub async fn read_attribute(args: &Args, context: CallContext<'_>) -> ApiResult {
    let node_id = require_node(args, context)?;
    let paths = parse_path_arg(args)?;
    let fabric_filtered = args.bool_or("fabric_filtered", false)?;

    let attributes = context
        .server
        .matter
        .read_attributes(
            node_id,
            paths.iter().map(|path| path.to_attr_path()).collect(),
            fabric_filtered,
        )
        .await?;

    // A read is also the freshest view of these attributes, so the cached node
    // is updated and any change is announced. Clients rely on that to stay in
    // sync without polling.
    publish_attribute_changes(context, node_id, &attributes);

    Ok(serde_json::to_value(attributes).unwrap_or(Value::Null))
}

/// Write one attribute.
///
/// The response uses capitalised `Path`/`Status` keys. That differs from the
/// snake_case shape `set_acl_entry` and `set_node_binding` return, but it is
/// what the reference sends and what clients parse.
pub async fn write_attribute(args: &Args, context: CallContext<'_>) -> ApiResult {
    let node_id = require_node(args, context)?;
    let (endpoint, cluster, attribute) = parse_write_path(args)?;
    let value = args
        .value("value")
        .ok_or_else(|| ApiError::invalid_args("Missing value"))?;
    let timed_timeout_ms = timed_timeout(args)?;

    let encoded = tlv_json::attribute_value_from_json(cluster, attribute, &value)?;
    let status = context
        .server
        .matter
        .write_attribute(
            node_id,
            endpoint,
            cluster,
            attribute,
            encoded,
            timed_timeout_ms,
        )
        .await?;

    if status == 0 {
        let path = format_path(endpoint, cluster, attribute);
        if context
            .server
            .nodes
            .set_attribute(node_id, &path, value.clone())
            .is_some()
        {
            context
                .server
                .events
                .publish(Event::attribute_updated(node_id, &path, value));
        }
    }

    Ok(json!([{
        "Path": {
            "EndpointId": endpoint,
            "ClusterId": cluster,
            "AttributeId": attribute,
        },
        "Status": status,
    }]))
}

/// Invoke a cluster command.
///
/// `command_name` is resolved against the cluster metadata, so payload fields
/// are addressed by name exactly as the reference accepts them. A cluster this
/// build has no metadata for is still reachable by passing a numeric command
/// id and numeric payload keys.
pub async fn device_command(args: &Args, context: CallContext<'_>) -> ApiResult {
    let node_id = require_node(args, context)?;
    let endpoint = args
        .u16("endpoint_id")?
        .or(args.u16("endpoint")?)
        .ok_or_else(|| ApiError::invalid_args("Missing endpoint_id"))?;
    let cluster = args
        .u32("cluster_id")?
        .or(args.u32("cluster")?)
        .ok_or_else(|| ApiError::invalid_args("Missing cluster_id"))?;
    let payload = args.value("payload").unwrap_or(Value::Null);
    let timed_timeout_ms = timed_timeout(args)?;

    let name = args.str("command_name")?.or(args.str("command")?);
    let numeric_id = args.u32("command_id")?;

    let meta = clusters::cluster(cluster).and_then(|cluster| {
        name.and_then(|name| cluster.command(name))
            .or_else(|| numeric_id.and_then(|id| cluster.command_by_id(id)))
    });

    let (command_id, encoded, response_names) = match meta {
        Some(command) => (
            command.id,
            tlv_json::command_payload_from_json(command, &payload)?,
            command.response_fields.clone(),
        ),
        None => {
            // No metadata: the caller must address the command numerically,
            // either through `command_id` or a numeric `command_name`.
            let command_id = numeric_id
                .or_else(|| name.and_then(|name| name.parse::<u32>().ok()))
                .ok_or_else(|| {
                    ApiError::invalid_args(match name {
                        Some(name) => format!("Unknown command '{}' for cluster {}", name, cluster),
                        None => "Missing command_name".to_string(),
                    })
                })?;
            (
                command_id,
                tlv_json::from_json(&payload, &clusters::FieldKind::Other)?,
                BTreeMap::new(),
            )
        }
    };

    let encoded = match encoded {
        // A payload that is not a struct is not addressable by the Interaction
        // Model; commands always carry a (possibly empty) struct.
        TlvNode::Struct(_) => encoded,
        _ => return Err(ApiError::invalid_args("payload must be an object")),
    };

    let sent = std::time::Instant::now();
    let response = context
        .server
        .matter
        .invoke(
            node_id,
            endpoint,
            cluster,
            command_id,
            encoded,
            timed_timeout_ms,
            response_names,
        )
        .await?;

    // A subscribed node reports the command's effect itself; it is read back
    // only if it does not (see `crate::confirm`). One without a subscription
    // is read back at once, or nothing would tell clients until the next poll.
    let after = if context.server.subscriptions.holds(node_id) {
        crate::confirm::REPORT_WITHIN
    } else {
        std::time::Duration::ZERO
    };
    context
        .server
        .confirmations
        .request(node_id, endpoint, sent, after);
    Ok(response)
}

/// Give this controller a Matter group's key (an rs-matter-server extension):
/// `group_id`, `key_set_id` and `epoch_key` (base64, 16 bytes), the same key
/// set the group's members were given with `KeySetWrite`. Kept in memory only.
pub async fn set_group_key(args: &Args, context: CallContext<'_>) -> ApiResult {
    use base64::Engine as _;

    let group_id = args
        .u16("group_id")?
        .ok_or_else(|| ApiError::invalid_args("Missing group_id"))?;
    let key_set_id = args
        .u16("key_set_id")?
        .ok_or_else(|| ApiError::invalid_args("Missing key_set_id"))?;
    let epoch_key = args
        .str("epoch_key")?
        .ok_or_else(|| ApiError::invalid_args("Missing epoch_key"))?;
    let epoch_key = base64::engine::general_purpose::STANDARD
        .decode(epoch_key)
        .map_err(|_| ApiError::invalid_args("epoch_key must be base64"))?;
    context
        .server
        .matter
        .set_group_key(group_id, key_set_id, epoch_key)
        .await?;
    Ok(Value::Null)
}

/// Send a command to a Matter group as one multicast message (an
/// rs-matter-server extension): `group_id`, `cluster_id`, `command_name` (or
/// `command_id`) and `payload`, as for `device_command` but with no endpoint;
/// `node_ids`, the group's members.
///
/// The message goes out of every interface that leads to a member (see
/// [`crate::matter::groupcast`]), worked out from the members' last known
/// operational addresses. Returns once it is out, with the interfaces used
/// and the members with no known address, which it can't have reached;
/// members don't answer.
pub async fn group_command(args: &Args, context: CallContext<'_>) -> ApiResult {
    use crate::matter::groupcast;

    let group_id = args
        .u16("group_id")?
        .ok_or_else(|| ApiError::invalid_args("Missing group_id"))?;
    let node_ids: Vec<u64> = match args.value("node_ids") {
        Some(Value::Array(ids)) => ids
            .iter()
            .map(|id| {
                id.as_u64()
                    .ok_or_else(|| ApiError::invalid_args("node_ids must be integers"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(ApiError::invalid_args("Missing node_ids")),
    };
    let cluster = args
        .u32("cluster_id")?
        .ok_or_else(|| ApiError::invalid_args("Missing cluster_id"))?;
    let payload = args.value("payload").unwrap_or(Value::Null);
    let name = args.str("command_name")?;
    let numeric_id = args.u32("command_id")?;
    let command = clusters::cluster(cluster)
        .and_then(|cluster| {
            name.and_then(|name| cluster.command(name))
                .or_else(|| numeric_id.and_then(|id| cluster.command_by_id(id)))
        })
        .ok_or_else(|| ApiError::invalid_args("Unknown command"))?;
    let encoded = tlv_json::command_payload_from_json(command, &payload)?;
    if !matches!(encoded, TlvNode::Struct(_)) {
        return Err(ApiError::invalid_args("payload must be an object"));
    }

    let mut unaddressed = Vec::new();
    let mut addresses = Vec::new();
    for &node_id in &node_ids {
        let known = context.server.nodes.ip_addresses(node_id);
        if known.iter().all(|a| groupcast::parse_address(a).is_none()) {
            unaddressed.push(node_id);
        }
        addresses.extend(known);
    }
    let interfaces = groupcast::interfaces_for(addresses.iter().map(String::as_str));
    if interfaces.is_empty() {
        return Err(ApiError::invalid_args(
            "No member has a known IPv6 address to route the group message by",
        ));
    }
    let fabric = context.server.fabric_info().await?;
    let address = rs_matter::utils::ipv6::compute_group_multicast_addr(fabric.fabric_id, group_id);
    context.server.group_routes.set(address, interfaces.clone());

    context
        .server
        .matter
        .group_invoke(group_id, cluster, command.id, encoded)
        .await?;
    Ok(json!({
        "interfaces": interfaces.iter().map(|&i| groupcast::interface_name(i)).collect::<Vec<_>>(),
        "unaddressed_node_ids": unaddressed,
    }))
}

/// Timed interactions are requested in milliseconds and capped at what the
/// Interaction Model can carry.
fn timed_timeout(args: &Args) -> Result<Option<u16>, ApiError> {
    let Some(timeout) = args.u64("timed_request_timeout_ms")? else {
        return Ok(None);
    };
    if timeout == 0 {
        return Ok(None);
    }
    Ok(Some(timeout.min(u16::MAX as u64) as u16))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests_support::{call, test_context};
    use crate::protocol::model::MatterNodeData;
    use crate::storage::StoredNode;
    use futures_lite::future::block_on;

    fn context_with_node() -> crate::api::ServerContext {
        let context = test_context();
        context.nodes.upsert(StoredNode::new(MatterNodeData::new(
            1,
            "2026-01-01T00:00:00.000Z".into(),
        )));
        context
    }

    #[test]
    fn reads_require_a_known_node_and_a_path() {
        let context = context_with_node();
        let args = Args::new(json!({ "node_id": 2, "attribute_path": "1/6/0" }));
        assert_eq!(
            block_on(read_attribute(&args, call(&context)))
                .unwrap_err()
                .code
                .as_i64(),
            5
        );

        let args = Args::new(json!({ "node_id": 1 }));
        let error = block_on(read_attribute(&args, call(&context))).unwrap_err();
        assert_eq!(error.code.as_i64(), 8);
        assert!(error.details.contains("Missing attribute_path"));
    }

    #[test]
    fn writes_reject_wildcards_before_reaching_matter() {
        let context = context_with_node();
        let args = Args::new(json!({
            "node_id": 1,
            "attribute_path": "1/6/*",
            "value": true
        }));
        let error = block_on(write_attribute(&args, call(&context))).unwrap_err();
        assert_eq!(error.code.as_i64(), 8);
        assert!(error.details.contains("wildcards"));
    }

    #[test]
    fn writes_require_a_value() {
        let context = context_with_node();
        let args = Args::new(json!({ "node_id": 1, "attribute_path": "1/6/16385" }));
        let error = block_on(write_attribute(&args, call(&context))).unwrap_err();
        assert!(error.details.contains("Missing value"));
    }

    #[test]
    fn an_unknown_command_name_is_rejected_with_the_cluster_named() {
        let context = context_with_node();
        let args = Args::new(json!({
            "node_id": 1,
            "endpoint_id": 1,
            "cluster_id": 6,
            "command_name": "explode",
            "payload": {}
        }));
        let error = block_on(device_command(&args, call(&context))).unwrap_err();
        assert_eq!(error.code.as_i64(), 8);
        assert!(error.details.contains("Unknown command 'explode'"));
    }

    #[test]
    fn an_unknown_payload_field_is_rejected_rather_than_dropped() {
        let context = context_with_node();
        let args = Args::new(json!({
            "node_id": 1,
            "endpoint_id": 1,
            "cluster_id": 8,
            "command_name": "moveToLevelWithOnOff",
            "payload": { "brightness": 128 }
        }));
        let error = block_on(device_command(&args, call(&context))).unwrap_err();
        assert_eq!(error.code.as_i64(), 8);
        assert!(error.details.contains("Unknown field 'brightness'"));
    }

    #[test]
    fn commands_need_an_endpoint_and_a_cluster() {
        let context = context_with_node();
        let args = Args::new(json!({ "node_id": 1, "cluster_id": 6, "command_name": "on" }));
        assert!(block_on(device_command(&args, call(&context)))
            .unwrap_err()
            .details
            .contains("Missing endpoint_id"));
    }

    #[test]
    fn observed_attributes_are_cached_and_announced_exactly_once() {
        let context = context_with_node();
        let events = context.events.subscribe();

        let mut attributes = AttributesData::new();
        attributes.insert("1/6/0".into(), json!(true));
        assert!(publish_attribute_changes(call(&context), 1, &attributes));

        let event = events.try_recv().unwrap();
        assert_eq!(event.payload["data"], json!([1, "1/6/0", true]));
        // The value is cached, so re-observing it announces nothing.
        assert_eq!(
            context.nodes.get(1).unwrap().attributes["1/6/0"],
            json!(true)
        );
        assert!(!publish_attribute_changes(call(&context), 1, &attributes));
        assert!(events.try_recv().is_err());

        // A real change is announced again.
        attributes.insert("1/6/0".into(), json!(false));
        assert!(publish_attribute_changes(call(&context), 1, &attributes));
        assert_eq!(
            events.try_recv().unwrap().payload["data"],
            json!([1, "1/6/0", false])
        );
    }

    #[test]
    fn timed_requests_are_capped_and_zero_means_untimed() {
        assert_eq!(
            timed_timeout(&Args::new(json!({ "timed_request_timeout_ms": 0 }))).unwrap(),
            None
        );
        assert_eq!(
            timed_timeout(&Args::new(json!({ "timed_request_timeout_ms": 3000 }))).unwrap(),
            Some(3000)
        );
        assert_eq!(
            timed_timeout(&Args::new(json!({ "timed_request_timeout_ms": 100000 }))).unwrap(),
            Some(u16::MAX)
        );
    }
}
