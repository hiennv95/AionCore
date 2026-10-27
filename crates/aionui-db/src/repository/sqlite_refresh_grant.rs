use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::RefreshGrantRow;
use crate::repository::refresh_grant::{GrantPair, IRefreshGrantRepository};

/// SQLite-backed implementation of [`IRefreshGrantRepository`].
#[derive(Clone, Debug)]
pub struct SqliteRefreshGrantRepository {
    pool: SqlitePool,
}

impl SqliteRefreshGrantRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IRefreshGrantRepository for SqliteRefreshGrantRepository {
    async fn create(
        &self,
        id: &str,
        user_id: &str,
        device_id: Option<&str>,
        pair: GrantPair<'_>,
        now_ms: i64,
    ) -> Result<RefreshGrantRow, DbError> {
        Ok(sqlx::query_as(
            "INSERT INTO refresh_grants \
             (id, user_id, device_id, current_jti, issued_at, access_expires_at, refresh_expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(id)
        .bind(user_id)
        .bind(device_id)
        .bind(pair.jti)
        .bind(pair.issued_at)
        .bind(pair.access_expires_at)
        .bind(pair.refresh_expires_at)
        .bind(now_ms)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn find(&self, id: &str) -> Result<Option<RefreshGrantRow>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM refresh_grants WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn rotate(&self, id: &str, expected_jti: &str, next: GrantPair<'_>, now_ms: i64) -> Result<bool, DbError> {
        let done = sqlx::query(
            "UPDATE refresh_grants SET previous_jti = current_jti, rotated_at = ?, current_jti = ?, \
               issued_at = ?, access_expires_at = ?, refresh_expires_at = ? \
             WHERE id = ? AND current_jti = ? AND revoked_at IS NULL",
        )
        .bind(now_ms)
        .bind(next.jti)
        .bind(next.issued_at)
        .bind(next.access_expires_at)
        .bind(next.refresh_expires_at)
        .bind(id)
        .bind(expected_jti)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    async fn revoke(&self, id: &str, now_ms: i64) -> Result<bool, DbError> {
        let done = sqlx::query("UPDATE refresh_grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now_ms)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }
}
