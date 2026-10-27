#![warn(clippy::disallowed_types)]

//! Local attention inbox (B05, ADR-018): approvals and questions agents are waiting on
//! right now, plus how unseen turns ended, across every chat of the owner.
pub mod error;
pub mod receipt;
pub mod routes;
pub mod service;
pub mod state;
pub mod workspace;

pub use error::InboxError;
pub use receipt::ReceiptService;
pub use routes::inbox_routes;
pub use service::InboxService;
pub use state::InboxRouterState;
