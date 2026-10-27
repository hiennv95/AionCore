#![warn(clippy::disallowed_types)]

//! Preview v1 (ADR-017): host-minted refs to files an agent produced in a chat, and reading them
//! back as text, Markdown or images after re-checking they are still the file inside the chat folder.
pub mod error;
pub mod kind;
pub mod routes;
pub mod service;
pub mod state;

pub use error::PreviewError;
pub use routes::preview_routes;
pub use service::{PreviewContent, PreviewService};
pub use state::PreviewRouterState;
