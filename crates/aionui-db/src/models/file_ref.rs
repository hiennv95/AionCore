use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for `conversation_file_refs` (ADR-017). `rel_path` is relative to
/// `workspace_canonical`, which is the canonical workspace at minting time.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConversationFileRefRow {
    pub id: String,
    pub conversation_id: String,
    pub rel_path: String,
    pub workspace_canonical: String,
    pub call_id: Option<String>,
    pub size: i64,
    pub mtime_ms: TimestampMs,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}
