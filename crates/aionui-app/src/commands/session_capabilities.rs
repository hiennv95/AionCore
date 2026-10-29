use aionui_api_types::{SESSION_TOOLS_SCHEMA_VERSION, SessionToolErrorCode, session_tool_descriptors};
use serde_json::{Value, json};

pub(crate) fn data() -> Value {
    let tools = session_tool_descriptors()
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "cli_command": tool.cli_command,
                "description": tool.description,
                "when": tool.when,
                "input_summary": tool.input_summary,
                "stdin_json_schema": tool.input_schema,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": SESSION_TOOLS_SCHEMA_VERSION,
        "contract": "agent-facing-session-cli",
        "commands": {
            "capabilities": { "runtime_env_required": [] },
            "list": { "runtime_env_required": ["AIONUI_BASE_URL", "AIONUI_USER_ID", "AIONUI_CONVERSATION_ID", "AIONUI_RUNTIME_TOKEN"] },
            "send-message": { "runtime_env_required": ["AIONUI_BASE_URL", "AIONUI_USER_ID", "AIONUI_CONVERSATION_ID", "AIONUI_RUNTIME_TOKEN"] }
        },
        "output_envelope": {
            "success": "boolean",
            "data": "object when success=true",
            "error": "object when success=false",
            "meta": { "schema_version": SESSION_TOOLS_SCHEMA_VERSION }
        },
        "delivery_status": {
            "delivered": "turn claim taken, message persisted, prompt dispatched (or merged into the target's running turn)",
            "queued": "target not ready yet — busy and unable to take a mid-turn message, waiting on a confirmation card, or restarting its runtime; queued in memory and retried until it frees up"
        },
        "tools": tools,
        // Serialized from the enum, so every wire value is listed and nothing else.
        "errors": SessionToolErrorCode::ALL,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `capabilities` is the agent's fallback for exact schemas, so every wired
    /// command must appear in it — otherwise the fallback points nowhere.
    #[test]
    fn capabilities_lists_every_registry_tool_and_its_cli_path() {
        let data = data();
        let tools = data["tools"].as_array().unwrap();
        assert_eq!(tools.len(), session_tool_descriptors().len());
        for descriptor in session_tool_descriptors() {
            let entry = tools
                .iter()
                .find(|tool| tool["name"] == serde_json::json!(descriptor.name))
                .unwrap_or_else(|| panic!("{} missing from capabilities", descriptor.name));
            assert_eq!(
                entry["cli_command"],
                serde_json::to_value(&descriptor.cli_command).unwrap()
            );
            assert!(entry["stdin_json_schema"].is_object(), "{}", descriptor.name);
        }
    }

    /// `capabilities` itself must need no runtime env — spec §6.9.2 requires it
    /// to work even when the feature is switched off.
    #[test]
    fn capabilities_declares_that_it_needs_no_runtime_env() {
        let data = data();
        assert_eq!(
            data["commands"]["capabilities"]["runtime_env_required"],
            serde_json::json!([])
        );
    }

    #[test]
    fn every_error_code_is_documented_with_its_wire_value() {
        let documented = data()["errors"].clone();
        let wire: Vec<Value> = SessionToolErrorCode::ALL
            .iter()
            .map(|code| serde_json::to_value(code).unwrap())
            .collect();
        assert_eq!(documented, json!(wire));
        // The refusal the LAN-share helper gets from `session send` and `session list`.
        assert!(wire.contains(&json!("helper_not_for_lan_share")), "{documented}");
    }
}
