use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for `devices` (ADR-011). `kind` is `desktop_app`, `mobile` or `browser`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub kind: String,
    pub created_at: TimestampMs,
    pub last_seen_at: TimestampMs,
    pub revoked_at: Option<TimestampMs>,
}
