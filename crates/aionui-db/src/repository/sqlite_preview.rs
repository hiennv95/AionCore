use aionui_common::{generate_prefixed_id, now_ms};
use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::ConversationFileRefRow;
use crate::repository::preview::{IPreviewRepository, UpsertFileRefParams};

/// SQLite-backed implementation of [`IPreviewRepository`].
#[derive(Clone, Debug)]
pub struct SqlitePreviewRepository {
    pool: SqlitePool,
}

impl SqlitePreviewRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IPreviewRepository for SqlitePreviewRepository {
    async fn upsert_file_ref(&self, p: UpsertFileRefParams<'_>) -> Result<ConversationFileRefRow, DbError> {
        let now = now_ms();
        Ok(sqlx::query_as(
            "INSERT INTO conversation_file_refs \
             (id, conversation_id, rel_path, workspace_canonical, call_id, size, mtime_ms, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (conversation_id, rel_path) DO UPDATE SET \
               workspace_canonical = excluded.workspace_canonical, call_id = excluded.call_id, \
               size = excluded.size, mtime_ms = excluded.mtime_ms, updated_at = excluded.updated_at \
             RETURNING *",
        )
        .bind(generate_prefixed_id("pf"))
        .bind(p.conversation_id)
        .bind(p.rel_path)
        .bind(p.workspace_canonical)
        .bind(p.call_id)
        .bind(p.size)
        .bind(p.mtime_ms)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn list_file_refs(&self, conversation_id: &str) -> Result<Vec<ConversationFileRefRow>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM conversation_file_refs WHERE conversation_id = ? ORDER BY updated_at DESC, id DESC",
        )
        .bind(conversation_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn find_file_ref(&self, conversation_id: &str, id: &str) -> Result<Option<ConversationFileRefRow>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM conversation_file_refs WHERE conversation_id = ? AND id = ?")
                .bind(conversation_id)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn devices_allowed(&self, user_id: &str) -> Result<bool, DbError> {
        let allowed: Option<i64> = sqlx::query_scalar("SELECT devices_allowed FROM preview_settings WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(allowed.unwrap_or(0) != 0)
    }

    async fn set_devices_allowed(&self, user_id: &str, allowed: bool) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO preview_settings (user_id, devices_allowed, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT (user_id) DO UPDATE SET devices_allowed = excluded.devices_allowed, \
             updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(i64::from(allowed))
        .bind(now_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
