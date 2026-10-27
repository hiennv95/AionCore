use aionui_common::TimestampMs;
use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::TurnOutcomeRow;
use crate::repository::turn_outcome::{ITurnOutcomeRepository, RecordTurnOutcomeParams};

/// SQLite-backed implementation of [`ITurnOutcomeRepository`].
#[derive(Clone, Debug)]
pub struct SqliteTurnOutcomeRepository {
    pool: SqlitePool,
}

impl SqliteTurnOutcomeRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ITurnOutcomeRepository for SqliteTurnOutcomeRepository {
    async fn record(&self, p: RecordTurnOutcomeParams<'_>) -> Result<bool, DbError> {
        let result = sqlx::query(
            "INSERT INTO turn_outcomes \
             (turn_id, user_id, conversation_id, outcome, source, error_code, ended_at, seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL) \
             ON CONFLICT (turn_id) DO UPDATE SET \
               outcome = excluded.outcome, source = excluded.source, \
               error_code = excluded.error_code, ended_at = excluded.ended_at \
             WHERE turn_outcomes.outcome != 'stopped' \
               AND turn_outcomes.user_id = excluded.user_id \
               AND NOT (turn_outcomes.outcome = excluded.outcome \
                        AND turn_outcomes.source = excluded.source \
                        AND turn_outcomes.error_code IS excluded.error_code)",
        )
        .bind(p.turn_id)
        .bind(p.user_id)
        .bind(p.conversation_id)
        .bind(p.outcome)
        .bind(p.source)
        .bind(p.error_code)
        .bind(p.ended_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_unseen(&self, user_id: &str, limit: u32) -> Result<Vec<TurnOutcomeRow>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM turn_outcomes \
             WHERE user_id = ? AND seen_at IS NULL AND outcome IN ('finished', 'failed') \
             ORDER BY ended_at DESC, turn_id DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?)
    }

    async fn mark_seen(&self, user_id: &str, conversation_id: &str, at: TimestampMs) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE turn_outcomes SET seen_at = ? \
             WHERE user_id = ? AND conversation_id = ? AND seen_at IS NULL",
        )
        .bind(at)
        .bind(user_id)
        .bind(conversation_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
