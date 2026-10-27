use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::ConversationFileRefRow;

/// Values recorded when a reported file is minted (ADR-017).
#[derive(Debug, Clone)]
pub struct UpsertFileRefParams<'a> {
    pub conversation_id: &'a str,
    pub rel_path: &'a str,
    pub workspace_canonical: &'a str,
    pub call_id: Option<&'a str>,
    pub size: i64,
    pub mtime_ms: TimestampMs,
}

/// Data access for Preview v1: file refs per conversation and the owner's device setting.
#[async_trait::async_trait]
pub trait IPreviewRepository: Send + Sync {
    /// Insert, or refresh the call id, size and mtime of the existing ref for the same path.
    async fn upsert_file_ref(&self, params: UpsertFileRefParams<'_>) -> Result<ConversationFileRefRow, DbError>;
    /// Newest first.
    async fn list_file_refs(&self, conversation_id: &str) -> Result<Vec<ConversationFileRefRow>, DbError>;
    async fn find_file_ref(&self, conversation_id: &str, id: &str) -> Result<Option<ConversationFileRefRow>, DbError>;
    /// `false` when the owner never set it.
    async fn devices_allowed(&self, user_id: &str) -> Result<bool, DbError>;
    async fn set_devices_allowed(&self, user_id: &str, allowed: bool) -> Result<(), DbError>;
}
