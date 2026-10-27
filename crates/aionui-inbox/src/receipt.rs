//! Result receipts (B05.R1): what the host observed when a turn ended, kept apart from
//! what the agent claims and from the owner's acceptance.
use std::path::PathBuf;
use std::sync::Arc;

use aionui_api_types::{ReceiptFile, ReceiptTool, ReceiptWorkspace, TurnReceipt};
use aionui_db::{
    IConversationRepository, IPreviewRepository, ITurnOutcomeRepository, ITurnReceiptRepository,
    RecordTurnReceiptParams, TurnReceiptRow,
};
use tracing::{error, info};

use crate::error::InboxError;
use crate::workspace::{WorkspaceRead, read_workspace};

/// Longest agent message kept in a receipt, in characters.
const CLAIM_CHARS: usize = 4000;

pub struct ReceiptService {
    receipts: Arc<dyn ITurnReceiptRepository>,
    outcomes: Arc<dyn ITurnOutcomeRepository>,
    conversations: Arc<dyn IConversationRepository>,
    previews: Arc<dyn IPreviewRepository>,
}

impl ReceiptService {
    pub fn new(
        receipts: Arc<dyn ITurnReceiptRepository>,
        outcomes: Arc<dyn ITurnOutcomeRepository>,
        conversations: Arc<dyn IConversationRepository>,
        previews: Arc<dyn IPreviewRepository>,
    ) -> Self {
        Self {
            receipts,
            outcomes,
            conversations,
            previews,
        }
    }

    /// The chat folder recorded on the conversation, if any.
    async fn workspace_of(&self, user_id: &str, conversation_id: &str) -> Result<Option<PathBuf>, InboxError> {
        let Some(row) = self.conversations.get(user_id, conversation_id).await? else {
            return Err(InboxError::ConversationNotFound);
        };
        let extra: serde_json::Value = serde_json::from_str(&row.extra).unwrap_or_default();
        Ok(extra
            .get("workspace")
            .and_then(|w| w.as_str())
            .filter(|w| !w.is_empty())
            .map(PathBuf::from))
    }

    async fn read(path: Option<PathBuf>) -> WorkspaceRead {
        match path {
            Some(path) => tokio::task::spawn_blocking(move || read_workspace(&path))
                .await
                .unwrap_or(WorkspaceRead::Unknown),
            None => WorkspaceRead::Unknown,
        }
    }

    /// Records the turn's observations once, when it ended.
    pub async fn record(&self, user_id: &str, conversation_id: &str, turn_id: &str, started_at: i64) {
        let path = match self.workspace_of(user_id, conversation_id).await {
            Ok(path) => path,
            Err(e) => {
                error!(conversation_id, turn_id, error = %e, "receipt: conversation unreadable");
                return;
            }
        };
        let read = Self::read(path).await;
        let (head, fingerprint) = match &read {
            WorkspaceRead::Git { head, fingerprint } => (head.as_deref(), Some(fingerprint.as_str())),
            _ => (None, None),
        };
        let params = RecordTurnReceiptParams {
            turn_id,
            conversation_id,
            started_at,
            workspace_state: read.state(),
            workspace_head: head,
            workspace_fingerprint: fingerprint,
        };
        match self.receipts.record(params).await {
            Ok(()) => info!(conversation_id, turn_id, workspace = read.state(), "receipt: recorded"),
            Err(e) => error!(conversation_id, turn_id, error = %e, "receipt: failed to record"),
        }
    }

    pub async fn receipt(
        &self,
        user_id: &str,
        conversation_id: &str,
        turn_id: &str,
    ) -> Result<TurnReceipt, InboxError> {
        let path = self.workspace_of(user_id, conversation_id).await?;
        let conversation = self
            .conversations
            .get(user_id, conversation_id)
            .await?
            .ok_or(InboxError::ConversationNotFound)?;
        let outcome = self
            .outcomes
            .get(user_id, turn_id)
            .await?
            .filter(|o| o.conversation_id == conversation_id)
            .ok_or(InboxError::ReceiptNotFound)?;
        let row = self
            .receipts
            .get(conversation_id, turn_id)
            .await?
            .ok_or(InboxError::ReceiptNotFound)?;
        let (from, to) = (row.started_at, outcome.ended_at);

        let files = self
            .previews
            .list_file_refs(conversation_id)
            .await?
            .into_iter()
            .filter(|f| f.updated_at >= from && f.updated_at <= to)
            .map(|f| ReceiptFile {
                id: f.id,
                rel_path: f.rel_path,
                size: f.size,
                updated_at: f.updated_at,
            })
            .collect();
        let tools = self
            .receipts
            .tool_messages_between(conversation_id, from, to)
            .await?
            .into_iter()
            .map(|m| tool_of(&m.id, &m.content))
            .collect();
        let agent_claim = self
            .receipts
            .last_assistant_text_between(conversation_id, from, to)
            .await?
            .and_then(|m| claim_of(&m.content));
        let workspace = Self::compare(&row, Self::read(path).await);

        Ok(TurnReceipt {
            turn_id: outcome.turn_id,
            conversation_id: conversation.id,
            conversation_name: conversation.name,
            outcome: outcome.outcome,
            source: outcome.source,
            error_code: outcome.error_code,
            started_at: from,
            ended_at: to,
            files,
            tools,
            agent_claim,
            workspace,
            accepted_at: row.accepted_at,
        })
    }

    /// The owner's own call on the result; it never marks a check as passed.
    pub async fn accept(&self, user_id: &str, conversation_id: &str, turn_id: &str) -> Result<i64, InboxError> {
        self.workspace_of(user_id, conversation_id).await?;
        if !self
            .receipts
            .accept(conversation_id, turn_id, aionui_common::now_ms())
            .await?
        {
            return Err(InboxError::ReceiptNotFound);
        }
        let row = self
            .receipts
            .get(conversation_id, turn_id)
            .await?
            .ok_or(InboxError::ReceiptNotFound)?;
        info!(conversation_id, turn_id, "receipt: accepted by the owner");
        Ok(row.accepted_at.unwrap_or_default())
    }

    fn compare(row: &TurnReceiptRow, now: WorkspaceRead) -> ReceiptWorkspace {
        let stale = match (&row.workspace_fingerprint, &now) {
            (Some(then), WorkspaceRead::Git { fingerprint, .. }) => Some(then != fingerprint),
            (Some(_), _) => Some(true),
            _ => None,
        };
        ReceiptWorkspace {
            state: row.workspace_state.clone(),
            head: row.workspace_head.clone(),
            stale,
        }
    }
}

/// A stored tool call (merge-patched `ToolCallEventData`): name, the agent's status, and an
/// exit code only when the stored call carries an integer `exit_code` in `args` or `input`.
fn tool_of(id: &str, content: &str) -> ReceiptTool {
    let value: serde_json::Value = serde_json::from_str(content).unwrap_or_default();
    let status = match value.get("status").and_then(|s| s.as_str()) {
        Some(s @ ("running" | "completed" | "error" | "canceled")) => s.to_owned(),
        _ => "unknown".to_owned(),
    };
    let reported_exit_code = ["args", "input"]
        .iter()
        .find_map(|key| value.get(*key)?.get("exit_code")?.as_i64());
    ReceiptTool {
        call_id: value.get("call_id").and_then(|v| v.as_str()).unwrap_or(id).to_owned(),
        name: value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        status,
        reported_exit_code,
    }
}

/// The text of a stored assistant message (a JSON string, or `{content}`), shortened.
fn claim_of(content: &str) -> Option<String> {
    let text = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(value) => value.get("content").and_then(|c| c.as_str())?.to_owned(),
        Err(_) => content.to_owned(),
    };
    let text = text.trim();
    (!text.is_empty()).then(|| text.chars().take(CLAIM_CHARS).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_keeps_the_agents_status_and_only_a_real_exit_code() {
        let started = r#"{"call_id":"exec-1","name":"Run flutter test","args":{"type":"commandExecution","exit_code":null},"status":"completed"}"#;
        let tool = tool_of("exec-1", started);
        assert_eq!(
            (tool.name.as_str(), tool.status.as_str(), tool.reported_exit_code),
            ("Run flutter test", "completed", None)
        );
        let with_code = r#"{"call_id":"exec-2","name":"Run","args":{"exit_code":1},"status":"error"}"#;
        assert_eq!(tool_of("exec-2", with_code).reported_exit_code, Some(1));
        let odd = r#"{"call_id":"x","status":"weird"}"#;
        assert_eq!(tool_of("x", odd).status, "unknown");
        assert_eq!(tool_of("fallback", "not json").call_id, "fallback");
    }

    #[test]
    fn the_claim_is_the_agents_text_shortened() {
        assert_eq!(
            claim_of(r#"{"content":" Done, all tests pass. "}"#).as_deref(),
            Some("Done, all tests pass.")
        );
        assert_eq!(claim_of(r#""plain""#).as_deref(), Some("plain"));
        assert_eq!(claim_of(r#"{"content":"  "}"#), None);
        assert_eq!(
            claim_of(&format!("{{\"content\":\"{}\"}}", "é".repeat(5000)))
                .unwrap()
                .chars()
                .count(),
            CLAIM_CHARS
        );
    }
}
