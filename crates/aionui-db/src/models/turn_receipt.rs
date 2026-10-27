use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for `turn_receipts` (B05.R1): host observations recorded when a turn ended.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TurnReceiptRow {
    pub turn_id: String,
    pub conversation_id: String,
    pub started_at: TimestampMs,
    /// `git`, `not_git` or `unknown`.
    pub workspace_state: String,
    pub workspace_head: Option<String>,
    pub workspace_fingerprint: Option<String>,
    pub accepted_at: Option<TimestampMs>,
}

/// A tool call stored in a turn's time window, as the host persisted it.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TurnToolMessageRow {
    pub id: String,
    pub content: String,
    pub status: Option<String>,
    pub created_at: TimestampMs,
}

/// The last assistant text stored in a turn's time window.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TurnTextMessageRow {
    pub content: String,
    pub created_at: TimestampMs,
}
