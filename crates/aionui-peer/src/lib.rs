#![warn(clippy::disallowed_types)]

//! Host identity and mutually authenticated TLS for host-to-host peers (private LAN).
pub mod error;
pub mod identity;
pub mod server;
pub mod tls;
pub mod trust;

pub use error::PeerError;
pub use identity::{Fingerprint, PeerIdentity};
pub use server::{HEADER_READ_TIMEOUT, MAX_TLS_CONNECTIONS, PeerCaller, serve_device_listener, serve_peer_listener};
pub use tls::{ServerPin, client_config, device_server_config, server_config};
pub use trust::{InMemoryTrustStore, TrustStore};

/// Version of the host-to-host peer protocol spoken on the peer listener.
pub const PEER_PROTOCOL_VERSION: u32 = 1;
