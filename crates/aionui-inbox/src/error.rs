use aionui_db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum InboxError {
    #[error("conversation not found")]
    ConversationNotFound,
    #[error("receipt not found")]
    ReceiptNotFound,
    #[error(transparent)]
    Database(#[from] DbError),
}
