//! Preview v1 (ADR-017): files an agent produced in a chat, read back through host-minted refs.

use serde::{Deserialize, Serialize};

use aionui_common::TimestampMs;

/// How a client should render a file; decided by the host, never by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewKind {
    Text,
    Markdown,
    Image,
    /// Shown by the platform viewer (ADR-025, Jev 061).
    Pdf,
    Unsupported,
}

/// One previewable file of a conversation. `rel_path` is for display only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConversationFileView {
    pub id: String,
    pub rel_path: String,
    pub preview_kind: PreviewKind,
    pub mime: String,
    pub size: u64,
    /// Over the preview cap for its kind: the content route answers 413.
    pub too_large: bool,
    pub call_id: Option<String>,
    /// The file changed or disappeared since the agent reported it.
    pub stale: bool,
    pub created_at: TimestampMs,
}

/// Owner setting for paired phones and browsers (ADR-017 D2: one host-wide switch, off by default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilePreviewSettings {
    pub devices_allowed: bool,
}

/// What a file diff compares (ADR-024): always the git HEAD blob against the file on disk now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDiffSource {
    HeadVsDisk,
}

/// `not_a_repo`: no git worktree inside the chat folder holds the file; there is no diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDiffStatus {
    Ok,
    NotARepo,
}

/// `absent`: the file is not in HEAD (untracked or new), so the diff adds every line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDiffBase {
    Head,
    Absent,
}

/// A unified diff of one previewable file. Headers are `a/<rel_path>` and `b/<rel_path>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileDiffView {
    pub source: FileDiffSource,
    pub status: FileDiffStatus,
    /// `None` when `status` is `not_a_repo`.
    pub base: Option<FileDiffBase>,
    pub diff: String,
    /// The diff was cut at the 256 KB output cap.
    pub truncated: bool,
}
