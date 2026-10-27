use serde::{Deserialize, Serialize};

/// Row of `refresh_grants` (ADR-022): one rotating refresh session. Holds no token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshGrantRow {
    pub id: String,
    pub user_id: String,
    pub device_id: Option<String>,
    pub current_jti: String,
    /// JWT `iat` of the current pair, seconds.
    pub issued_at: i64,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub previous_jti: Option<String>,
    /// When `previous_jti` was replaced, ms.
    pub rotated_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}
