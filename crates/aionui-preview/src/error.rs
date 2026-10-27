use thiserror::Error;

/// Preview failures. Messages never carry host paths.
#[derive(Debug, Error)]
pub enum PreviewError {
    #[error("conversation not found")]
    ConversationNotFound,
    /// Unknown ref, a ref of another conversation, or a file that no longer passes the checks.
    #[error("file not found")]
    FileNotFound,
    #[error("file is over the preview size limit")]
    TooLarge,
    #[error("file type cannot be previewed")]
    Unsupported,
    #[error(transparent)]
    Database(#[from] aionui_db::DbError),
    #[error("preview task failed: {0}")]
    Internal(String),
}
