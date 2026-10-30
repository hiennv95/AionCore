//! Tool input/output on its way to a client (L03.IO): redacted and bounded in a copy, in the live
//! stream and in message history alike.
//!
//! Persistence is NOT changed: rows keep the raw payload, and the agent's own context is never
//! touched. Only what leaves the host for a client is sanitized, by the one shared sanitizer
//! ([`aionui_common::tool_payload`]), so the live and history paths cannot disagree.
//!
//! Shapes are Core's own (`aionui-ai-agent` `protocol/events/tool_call.rs`):
//!
//! - `tool_call`: `{call_id, name, args?, input?, output?, description?, status}`. `call_id`, `status`
//!   and the shape are kept; `args`/`input`/`output` are bounded.
//! - `acp_tool_call`: `{update: {tool_call_id, status, title, raw_input, raw_output, content[]}}`.
//! - `acp_terminal_output`: `{terminal_id, command, output, truncated, exit_status}`; `tool_group`: entries.
//!   A front-truncated snapshot loses its partial first line (it may be the tail of a secret).
//!
//! `acp_permission` is NOT sanitized: an approver must see the whole command, and cutting its tail could
//! hide a dangerous part of it. It is a decision prompt, not tool output.
//!
//! A bounded field gets a sibling flag (`input_truncated`, `raw_output_truncated`, ...) that is only
//! present when something was cut, so a client can say so. Unknown keys are not touched.

use aionui_common::tool_payload::{Limits, redact_and_bound, redact_and_bound_text};
use serde_json::Value;

/// Names and titles are short labels; a bigger one is cut without a flag.
const LABEL_MAX_BYTES: usize = 4096;

/// Sanitizes the `data` of a `message.stream` payload when its `type` is a tool call.
pub(crate) fn sanitize_stream_payload(payload: &mut Value) {
    let Some(kind) = payload.get("type").and_then(Value::as_str).map(str::to_owned) else {
        return;
    };
    if let Some(data) = payload.get_mut("data") {
        sanitize_tool_data(&kind, data, Limits::BOUNDED);
    }
}

/// Sanitizes the JSON content of a persisted or replaced message row of the given `type`.
pub(crate) fn sanitize_message_content(kind: &str, content: &mut Value, limits: Limits) {
    sanitize_tool_data(kind, content, limits);
}

fn sanitize_tool_data(kind: &str, data: &mut Value, limits: Limits) {
    match kind {
        "tool_call" => {
            bound_fields(data, &["args", "input", "output"], limits, "_truncated");
            bound_labels(data, &["name", "description"], limits);
        }
        "acp_tool_call" => {
            if let Some(update) = data.get_mut("update") {
                bound_fields(
                    update,
                    &["raw_input", "raw_output", "content", "locations", "_meta"],
                    limits,
                    "_truncated",
                );
                bound_labels(update, &["title"], limits);
            }
            bound_fields(data, &["_meta"], limits, "_truncated");
        }
        // Terminal snapshots are command output: same treatment as a tool's output.
        "acp_terminal_output" => {
            drop_partial_first_line(data);
            bound_fields(data, &["output"], limits, "_truncated");
            bound_labels(data, &["command"], limits);
        }
        "tool_group" => {
            for entry in data.as_array_mut().into_iter().flatten() {
                bound_labels(entry, &["name", "description"], limits);
            }
        }
        _ => {}
    }
}

/// A front-truncated terminal snapshot (`truncated: true`) starts mid-line, possibly mid-secret (`en=VALUE`
/// after `tok` was dropped), where no rule can see the name: drop that partial first line, or the first
/// word of a single long line.
fn drop_partial_first_line(data: &mut Value) {
    if data.get("truncated").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let Some(Value::String(output)) = data.get_mut("output") else {
        return;
    };
    let cut = output
        .find('\n')
        .map(|p| p + 1)
        .or_else(|| {
            output
                .char_indices()
                .find(|(_, c)| c.is_whitespace())
                .map(|(p, c)| p + c.len_utf8())
        })
        .unwrap_or(output.len());
    output.drain(..cut);
}

/// Redacts and bounds each present field in place; `<field>_truncated: true` only when cut.
fn bound_fields(object: &mut Value, fields: &[&str], limits: Limits, flag_suffix: &str) {
    let Some(map) = object.as_object_mut() else { return };
    for field in fields {
        let Some(slot) = map.get_mut(*field) else { continue };
        if slot.is_null() {
            continue;
        }
        let bounded = redact_and_bound(std::mem::take(slot), limits);
        *slot = bounded.value;
        if bounded.truncated {
            map.insert(format!("{field}{flag_suffix}"), Value::Bool(true));
        }
    }
}

/// Labels are cut at `LABEL_MAX_BYTES` unless the caller asked for the unbounded (redact-only) form.
fn bound_labels(object: &mut Value, fields: &[&str], limits: Limits) {
    let Some(map) = object.as_object_mut() else { return };
    for field in fields {
        if let Some(Value::String(text)) = map.get_mut(*field) {
            let limits = Limits {
                max_bytes: if limits.max_bytes == usize::MAX {
                    usize::MAX
                } else {
                    LABEL_MAX_BYTES
                },
                ..limits
            };
            *text = redact_and_bound_text(text, limits).0;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn huge() -> String {
        "line of output\n".repeat(20_000)
    }

    #[test]
    fn a_tool_call_keeps_its_shape_and_loses_secrets_and_bulk() {
        let mut data = json!({
            "call_id": "toolu_1", "name": "Run curl", "status": "completed",
            "input": {"command": "curl -H 'Authorization: Bearer SECRETVALUE' x", "env": {"API_TOKEN": "ENVSECRET"}},
            "args": {"command": "ls"},
            "output": format!("{} password=hunter2", huge()),
        });
        sanitize_tool_data("tool_call", &mut data, Limits::BOUNDED);
        assert_eq!(data["call_id"], "toolu_1");
        assert_eq!(data["status"], "completed");
        assert_eq!(data["name"], "Run curl");
        assert_eq!(data["args"], json!({"command": "ls"}));
        assert!(data.get("args_truncated").is_none());
        assert!(data.get("input_truncated").is_none());
        assert_eq!(data["output_truncated"], true);
        let text = data.to_string();
        for leaked in ["SECRETVALUE", "ENVSECRET", "hunter2"] {
            assert!(!text.contains(leaked), "{leaked} leaked");
        }
        assert!(data["output"].as_str().unwrap().len() <= aionui_common::tool_payload::TOOL_FIELD_MAX_BYTES);
        assert!(text.len() < 200_000);
    }

    #[test]
    fn an_acp_tool_call_is_sanitized_under_update() {
        let mut data = json!({"session_id": "s", "update": {
            "session_update": "tool_call_update", "tool_call_id": "a1", "status": "completed", "title": "Run ls",
            "raw_input": {"command": "ls", "password": "p"},
            "raw_output": "ok",
            "content": [{"type": "content", "content": {"type": "text", "text": huge()}}, {"type": "diff", "path": "/w/x", "new_text": "n"}],
        }});
        sanitize_tool_data("acp_tool_call", &mut data, Limits::BOUNDED);
        let update = &data["update"];
        assert_eq!(update["tool_call_id"], "a1");
        assert_eq!(update["status"], "completed");
        assert_eq!(update["raw_output"], "ok");
        assert!(update.get("raw_output_truncated").is_none());
        assert_eq!(update["content_truncated"], true);
        assert!(!data.to_string().contains("\"p\""));
        serde_json::from_str::<Value>(&data.to_string()).expect("valid json");
    }

    #[test]
    fn terminal_output_meta_and_group_labels_are_sanitized() {
        let mut term = json!({"terminal_id": "t", "command": "run --password=pw1", "output": format!("{} token=tk1", huge()), "truncated": false, "exit_status": 0});
        sanitize_tool_data("acp_terminal_output", &mut term, Limits::BOUNDED);
        assert_eq!(term["output_truncated"], true);
        assert_eq!(term["exit_status"], 0);
        assert!(!term.to_string().contains("pw1") && !term.to_string().contains("tk1"));

        let mut acp = json!({"update": {"tool_call_id": "a", "_meta": {"claudeCode": {"toolResponse": {"stdout": huge()}}}}, "_meta": {"api_key": "k1"}});
        sanitize_tool_data("acp_tool_call", &mut acp, Limits::BOUNDED);
        assert_eq!(acp["update"]["_meta_truncated"], true);
        assert!(!acp.to_string().contains("k1"));

        let mut group =
            json!([{"call_id": "c", "name": "n".repeat(10_000), "status": "executing", "description": "d token=g1"}]);
        sanitize_tool_data("tool_group", &mut group, Limits::BOUNDED);
        assert!(group[0]["name"].as_str().unwrap().len() <= LABEL_MAX_BYTES);
        assert!(!group.to_string().contains("g1"));
        assert_eq!(group[0]["call_id"], "c");
    }

    /// Second review: `update.locations` was the one ACP list left unbounded.
    #[test]
    fn acp_locations_are_bounded() {
        let locations: Vec<Value> = (0..100_000)
            .map(|i| json!({"path": format!("/w/src/file-{i}.rs")}))
            .collect();
        let mut data = json!({"session_id": "s", "update": {"tool_call_id": "a", "locations": locations}});
        sanitize_tool_data("acp_tool_call", &mut data, Limits::BOUNDED);
        let size = serde_json::to_string(&data["update"]["locations"]).unwrap().len();
        assert!(
            size <= aionui_common::tool_payload::TOOL_FIELD_MAX_BYTES,
            "locations serialize to {size}"
        );
        assert_eq!(data["update"]["locations_truncated"], true);
        assert_eq!(data["update"]["locations"][0]["path"], "/w/src/file-0.rs");
    }

    /// A front-truncated terminal snapshot starts mid-line: `tok` of `token=VALUE` was dropped, so no
    /// rule can see the name. The partial first line must not reach the client.
    #[test]
    fn a_front_cut_terminal_snapshot_drops_its_partial_first_line() {
        let mut term =
            json!({"terminal_id": "t", "command": "env", "output": "en=FRAG1\nPATH=/bin\n", "truncated": true});
        sanitize_tool_data("acp_terminal_output", &mut term, Limits::BOUNDED);
        assert_eq!(term["output"], "PATH=/bin\n");
        // One long front-cut line: its first (partial) word goes.
        let mut term = json!({"terminal_id": "t", "output": "FRAG2 rest of\u{3000}line", "truncated": true});
        sanitize_tool_data("acp_terminal_output", &mut term, Limits::BOUNDED);
        assert_eq!(term["output"], "rest of\u{3000}line");
        let mut term = json!({"terminal_id": "t", "output": "\u{3000}x", "truncated": true});
        sanitize_tool_data("acp_terminal_output", &mut term, Limits::BOUNDED);
        assert_eq!(term["output"], "x", "a multi-byte space is cut on its boundary");
        // Not front-cut: the first line is whole and stays.
        let mut term = json!({"terminal_id": "t", "output": "first\nsecond", "truncated": false});
        sanitize_tool_data("acp_terminal_output", &mut term, Limits::BOUNDED);
        assert_eq!(term["output"], "first\nsecond");
    }

    #[test]
    fn unbounded_labels_are_redacted_but_not_cut() {
        let long = format!("{} x", "n".repeat(10_000));
        let mut data = json!({"name": long.clone(), "description": "password=zz"});
        sanitize_tool_data("tool_call", &mut data, Limits::UNBOUNDED_BYTES);
        assert_eq!(data["name"], long);
        assert!(!data.to_string().contains("zz"));
    }

    #[test]
    fn other_payloads_are_not_touched() {
        let mut payload = json!({"type": "content", "data": {"content": "token=abc"}});
        let before = payload.clone();
        sanitize_stream_payload(&mut payload);
        assert_eq!(payload, before);
        let mut payload = json!({"type": "tool_group", "data": {"agents": [{"name": "n"}]}});
        let before = payload.clone();
        sanitize_stream_payload(&mut payload);
        assert_eq!(payload, before);
    }

    #[test]
    fn live_frames_and_history_agree_and_merging_keeps_both_halves() {
        let running = json!({"call_id": "k", "name": "Run", "status": "running", "input": {"command": "cat big"}});
        let result = json!({"call_id": "k", "status": "completed", "output": format!("{} Bearer TOPSECRET", huge())});
        // History holds the merged row (RFC 7396 merge of the frames); live sends each frame on its own.
        let mut merged = running.clone();
        for (key, value) in result.as_object().unwrap() {
            merged[key] = value.clone();
        }
        let mut live_running = running.clone();
        let mut live_result = result.clone();
        let mut history = merged;
        sanitize_tool_data("tool_call", &mut live_running, Limits::BOUNDED);
        sanitize_tool_data("tool_call", &mut live_result, Limits::BOUNDED);
        sanitize_message_content("tool_call", &mut history, Limits::BOUNDED);
        // Merge the sanitized live frames the way a client does: later fields win.
        let mut client = live_running.clone();
        for (key, value) in live_result.as_object().unwrap() {
            client[key] = value.clone();
        }
        assert_eq!(
            client, history,
            "the client sees the same thing live and after a reload"
        );
        assert!(!history.to_string().contains("TOPSECRET"));
        assert_eq!(history["input"], json!({"command": "cat big"}));
        assert_eq!(history["output_truncated"], true);
    }

    #[test]
    fn a_stream_payload_is_sanitized_through_its_type() {
        let mut payload = json!({"type": "tool_call", "data": {"call_id": "k", "output": "Bearer ZZZ"}});
        sanitize_stream_payload(&mut payload);
        assert!(!payload.to_string().contains("ZZZ"));
        assert_eq!(payload["data"]["call_id"], "k");
    }

    #[test]
    fn the_full_fetch_keeps_all_bytes_but_still_redacts() {
        let mut data = json!({"call_id": "k", "output": format!("{} token=abc", huge())});
        sanitize_message_content("tool_call", &mut data, Limits::UNBOUNDED_BYTES);
        assert!(data.get("output_truncated").is_none());
        assert!(data["output"].as_str().unwrap().len() > 100_000);
        assert!(!data.to_string().contains("token=abc"));
    }
}
