use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::{TurnReceiptRow, TurnTextMessageRow, TurnToolMessageRow};

/// Host observations taken when a turn ended (B05.R1).
#[derive(Debug, Clone)]
pub struct RecordTurnReceiptParams<'a> {
    pub turn_id: &'a str,
    pub conversation_id: &'a str,
    pub started_at: TimestampMs,
    pub workspace_state: &'a str,
    pub workspace_head: Option<&'a str>,
    pub workspace_fingerprint: Option<&'a str>,
}

/// Result receipts: the stored observations plus the turn's messages by time window.
#[async_trait::async_trait]
pub trait ITurnReceiptRepository: Send + Sync {
    /// Store the observations once; a repeat for the same turn keeps the first and any acceptance.
    async fn record(&self, params: RecordTurnReceiptParams<'_>) -> Result<(), DbError>;
    async fn get(&self, conversation_id: &str, turn_id: &str) -> Result<Option<TurnReceiptRow>, DbError>;
    /// Set the owner's acceptance; returns `false` when the receipt does not exist.
    async fn accept(&self, conversation_id: &str, turn_id: &str, at: TimestampMs) -> Result<bool, DbError>;
    /// Tool-call messages of a conversation created inside `[from, to]`, oldest first.
    async fn tool_messages_between(
        &self,
        conversation_id: &str,
        from: TimestampMs,
        to: TimestampMs,
    ) -> Result<Vec<TurnToolMessageRow>, DbError>;
    /// The newest assistant text message of a conversation created inside `[from, to]`.
    async fn last_assistant_text_between(
        &self,
        conversation_id: &str,
        from: TimestampMs,
        to: TimestampMs,
    ) -> Result<Option<TurnTextMessageRow>, DbError>;
}
