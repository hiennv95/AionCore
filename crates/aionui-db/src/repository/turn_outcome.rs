use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::TurnOutcomeRow;

/// One turn's end, as observed by the host (B05).
#[derive(Debug, Clone)]
pub struct RecordTurnOutcomeParams<'a> {
    pub turn_id: &'a str,
    pub user_id: &'a str,
    pub conversation_id: &'a str,
    /// `finished`, `failed` or `stopped`.
    pub outcome: &'a str,
    pub source: &'a str,
    pub error_code: Option<&'a str>,
    pub ended_at: TimestampMs,
}

/// Turn outcomes for the attention inbox.
#[async_trait::async_trait]
pub trait ITurnOutcomeRepository: Send + Sync {
    /// Record a turn's end once. A repeat for the same turn updates it, except that a
    /// `stopped` row is never overwritten (the user's stop explains whatever came after),
    /// and a seen row stays seen. Returns `false` when nothing changed.
    async fn record(&self, params: RecordTurnOutcomeParams<'_>) -> Result<bool, DbError>;
    /// Unseen `finished`/`failed` outcomes of the user, newest first.
    async fn list_unseen(&self, user_id: &str, limit: u32) -> Result<Vec<TurnOutcomeRow>, DbError>;
    /// Mark every outcome of one conversation seen; returns how many changed.
    async fn mark_seen(&self, user_id: &str, conversation_id: &str, at: TimestampMs) -> Result<u64, DbError>;
}
