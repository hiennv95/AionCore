use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for `turn_outcomes` (B05): how one agent turn ended, by host signal.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TurnOutcomeRow {
    pub turn_id: String,
    pub user_id: String,
    pub conversation_id: String,
    /// `finished`, `failed` or `stopped`.
    pub outcome: String,
    /// The host signal the outcome came from (e.g. `relay_finish`, `user_cancel`).
    pub source: String,
    pub error_code: Option<String>,
    pub ended_at: TimestampMs,
    pub seen_at: Option<TimestampMs>,
}
