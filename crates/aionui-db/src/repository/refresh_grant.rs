use crate::error::DbError;
use crate::models::RefreshGrantRow;

/// The current pair's id and times; enough to re-sign it exactly.
#[derive(Debug, Clone, Copy)]
pub struct GrantPair<'a> {
    pub jti: &'a str,
    pub issued_at: i64,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}

/// Refresh-token rotation grants (ADR-022).
#[async_trait::async_trait]
pub trait IRefreshGrantRepository: Send + Sync {
    async fn create(
        &self,
        id: &str,
        user_id: &str,
        device_id: Option<&str>,
        pair: GrantPair<'_>,
        now_ms: i64,
    ) -> Result<RefreshGrantRow, DbError>;
    async fn find(&self, id: &str) -> Result<Option<RefreshGrantRow>, DbError>;
    /// Compare-and-swap: replaces the current pair only while it is still `expected_jti`
    /// and the grant is not revoked. `false` when another rotation or a revoke won.
    async fn rotate(&self, id: &str, expected_jti: &str, next: GrantPair<'_>, now_ms: i64) -> Result<bool, DbError>;
    /// `false` when missing or already revoked.
    async fn revoke(&self, id: &str, now_ms: i64) -> Result<bool, DbError>;
}
