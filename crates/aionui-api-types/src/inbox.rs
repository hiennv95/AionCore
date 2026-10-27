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
