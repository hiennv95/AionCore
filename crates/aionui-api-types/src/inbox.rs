//! Local attention inbox (B05, ADR-018): what is waiting for the owner across chats.
use aionui_common::Confirmation;
use serde::{Deserialize, Serialize};

/// An approval or question an agent is waiting on right now.
///
/// Read from the running agent itself: it disappears once answered, when the agent
/// stops, and after a host restart (such approvals can no longer be executed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxApproval {
    pub conversation_id: String,
    pub conversation_name: String,
    pub confirmation: Confirmation,
}

/// How a turn the owner has not looked at yet ended, by host signal.
///
/// `finished` only means no error signal ended the turn; it is not proof the
/// agent's work succeeded. User-stopped turns are never listed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxOutcome {
    pub turn_id: String,
    pub conversation_id: String,
    pub conversation_name: String,
    /// `finished` or `failed`.
    pub outcome: String,
    /// `relay_finish`, `relay_error`, `channel_closed`, `start_failed` or `settled_without_relay`.
    pub source: String,
    pub error_code: Option<String>,
    pub ended_at: i64,
}

/// Response for `GET /api/inbox`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxResponse {
    /// Newest chats first.
    pub approvals: Vec<InboxApproval>,
    /// Newest first, at most [`INBOX_OUTCOME_LIMIT`].
    pub outcomes: Vec<InboxOutcome>,
}

/// Most outcomes `GET /api/inbox` returns.
pub const INBOX_OUTCOME_LIMIT: u32 = 100;

/// Body for `POST /api/inbox/seen`: the owner looked at this chat.
#[derive(Debug, Clone, Deserialize)]
pub struct InboxSeenRequest {
    pub conversation_id: String,
}

/// Payload of the `inbox.changed` WebSocket event: re-read `GET /api/inbox`.
#[derive(Debug, Clone, Serialize)]
pub struct InboxChangedPayload {
    pub user_id: String,
    pub conversation_id: String,
}

/// A file the agent reported writing during the turn, re-checked by the host (B04 refs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptFile {
    pub id: String,
    pub rel_path: String,
    pub size: i64,
    pub updated_at: i64,
}

/// A tool call the agent made during the turn. `status` is the agent's own report
/// (`running`, `completed`, `error`, `canceled` or `unknown`); `reported_exit_code` is a
/// process exit code only when the agent's stored call carries one. Neither is a host check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptTool {
    pub call_id: String,
    pub name: String,
    pub status: String,
    pub reported_exit_code: Option<i64>,
}

/// The chat folder as the host read it when the turn ended, compared with now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptWorkspace {
    /// `git`, `not_git` or `unknown`.
    pub state: String,
    /// The commit the work tree was on, when it is a git repository with commits.
    pub head: Option<String>,
    /// `true` when the folder changed since the turn ended, `false` when it did not,
    /// `None` when it cannot be compared (not git, or unreadable now or then).
    pub stale: Option<bool>,
}

/// Result receipt of one turn (B05.R1): host observations, the agent's claims and the
/// owner's acceptance, kept apart. Acceptance never means a check passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnReceipt {
    pub turn_id: String,
    pub conversation_id: String,
    pub conversation_name: String,
    /// `finished`, `failed` or `stopped`, by host signal.
    pub outcome: String,
    pub source: String,
    pub error_code: Option<String>,
    pub started_at: i64,
    pub ended_at: i64,
    /// Host-checked files written in the turn.
    pub files: Vec<ReceiptFile>,
    /// Agent-reported tool calls in the turn, oldest first.
    pub tools: Vec<ReceiptTool>,
    /// The agent's last message of the turn, its own words (at most 4000 characters).
    pub agent_claim: Option<String>,
    pub workspace: ReceiptWorkspace,
    pub accepted_at: Option<i64>,
}
