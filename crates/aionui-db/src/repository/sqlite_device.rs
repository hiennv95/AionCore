use aionui_common::{TimestampMs, generate_prefixed_id, now_ms};
use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::DeviceRow;
use crate::repository::device::IDeviceRepository;

/// SQLite-backed implementation of [`IDeviceRepository`].
#[derive(Clone, Debug)]
pub struct SqliteDeviceRepository {
    pool: SqlitePool,
}

impl SqliteDeviceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IDeviceRepository for SqliteDeviceRepository {
    async fn insert(&self, user_id: &str, name: &str, kind: &str) -> Result<DeviceRow, DbError> {
        let now = now_ms();
        let row = DeviceRow {
            id: generate_prefixed_id("dev"),
            user_id: user_id.to_owned(),
            name: name.to_owned(),
            kind: kind.to_owned(),
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        };
        sqlx::query(
            "INSERT INTO devices (id, user_id, name, kind, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.user_id)
        .bind(&row.name)
        .bind(&row.kind)
        .bind(row.created_at)
        .bind(row.last_seen_at)
        .execute(&self.pool)
        .await?;
        Ok(row)
    }

    async fn find(&self, id: &str) -> Result<Option<DeviceRow>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn list(&self, user_id: &str) -> Result<Vec<DeviceRow>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC, id DESC")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn revoke(&self, user_id: &str, id: &str, now: TimestampMs) -> Result<bool, DbError> {
        let result =
            sqlx::query("UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL")
                .bind(now)
                .bind(id)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn touch(&self, id: &str, now: TimestampMs) -> Result<(), DbError> {
        sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_database_memory;

    #[tokio::test]
    async fn insert_list_and_revoke_are_scoped_to_the_user() {
        let db = init_database_memory().await.unwrap();
        let repo = SqliteDeviceRepository::new(db.pool().clone());
        let phone = repo.insert("owner", "Pixel", "mobile").await.unwrap();
        repo.insert("owner", "Mac app", "desktop_app").await.unwrap();
        repo.insert("other", "Their phone", "mobile").await.unwrap();

        assert_eq!(repo.list("owner").await.unwrap().len(), 2);
        assert!(
            !repo.revoke("other", &phone.id, 10).await.unwrap(),
            "another user cannot revoke"
        );
        assert!(repo.revoke("owner", &phone.id, 10).await.unwrap());
        assert!(
            !repo.revoke("owner", &phone.id, 11).await.unwrap(),
            "second revoke is a no-op"
        );
        assert_eq!(repo.find(&phone.id).await.unwrap().unwrap().revoked_at, Some(10));
        assert!(repo.find("dev_missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn touch_updates_last_seen() {
        let db = init_database_memory().await.unwrap();
        let repo = SqliteDeviceRepository::new(db.pool().clone());
        let device = repo.insert("owner", "Browser", "browser").await.unwrap();
        repo.touch(&device.id, device.last_seen_at + 5).await.unwrap();
        assert_eq!(
            repo.find(&device.id).await.unwrap().unwrap().last_seen_at,
            device.last_seen_at + 5
        );
    }
}
