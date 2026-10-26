use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::DeviceRow;

/// Data access for client devices (ADR-011).
#[async_trait::async_trait]
pub trait IDeviceRepository: Send + Sync {
    async fn insert(&self, user_id: &str, name: &str, kind: &str) -> Result<DeviceRow, DbError>;
    async fn find(&self, id: &str) -> Result<Option<DeviceRow>, DbError>;
    /// Newest first.
    async fn list(&self, user_id: &str) -> Result<Vec<DeviceRow>, DbError>;
    /// Mark revoked. `false` when missing, owned by someone else or already revoked.
    async fn revoke(&self, user_id: &str, id: &str, now: TimestampMs) -> Result<bool, DbError>;
    async fn touch(&self, id: &str, now: TimestampMs) -> Result<(), DbError>;
}
