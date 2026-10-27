use aionui_common::TimestampMs;
use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::{TurnReceiptRow, TurnTextMessageRow, TurnToolMessageRow};
use crate::repository::turn_receipt::{ITurnReceiptRepository, RecordTurnReceiptParams};

/// SQLite-backed implementation of [`ITurnReceiptRepository`].
#[derive(Clone, Debug)]
pub struct SqliteTurnReceiptRepository {
    pool: SqlitePool,
}

impl SqliteTurnReceiptRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ITurnReceiptRepository for SqliteTurnReceiptRepository {
    async fn record(&self, p: RecordTurnReceiptParams<'_>) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO turn_receipts \
             (turn_id, conversation_id, started_at, workspace_state, workspace_head, workspace_fingerprint) \
             VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (turn_id) DO NOTHING",
        )
        .bind(p.turn_id)
        .bind(p.conversation_id)
        .bind(p.started_at)
        .bind(p.workspace_state)
        .bind(p.workspace_head)
        .bind(p.workspace_fingerprint)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, conversation_id: &str, turn_id: &str) -> Result<Option<TurnReceiptRow>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM turn_receipts WHERE conversation_id = ? AND turn_id = ?")
                .bind(conversation_id)
                .bind(turn_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn accept(&self, conversation_id: &str, turn_id: &str, at: TimestampMs) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE turn_receipts SET accepted_at = COALESCE(accepted_at, ?) WHERE conversation_id = ? AND turn_id = ?",
        )
        .bind(at)
        .bind(conversation_id)
        .bind(turn_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn tool_messages_between(
        &self,
        conversation_id: &str,
        from: TimestampMs,
        to: TimestampMs,
    ) -> Result<Vec<TurnToolMessageRow>, DbError> {
        Ok(sqlx::query_as(
            "SELECT id, content, status, created_at FROM messages \
             WHERE conversation_id = ? AND type IN ('tool_call', 'acp_tool_call') \
               AND created_at BETWEEN ? AND ? \
             ORDER BY created_at ASC, id ASC LIMIT 500",
        )
        .bind(conversation_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn last_assistant_text_between(
        &self,
        conversation_id: &str,
        from: TimestampMs,
        to: TimestampMs,
    ) -> Result<Option<TurnTextMessageRow>, DbError> {
        Ok(sqlx::query_as(
            "SELECT content, created_at FROM messages \
             WHERE conversation_id = ? AND type = 'text' AND position = 'left' AND hidden = 0 \
               AND created_at BETWEEN ? AND ? \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(conversation_id)
        .bind(from)
        .bind(to)
        .fetch_optional(&self.pool)
        .await?)
    }
}
