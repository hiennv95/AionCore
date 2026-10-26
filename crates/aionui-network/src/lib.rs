#![warn(clippy::disallowed_types)]

//! Private-LAN host network (ADR-009): pairing, agent shares, the durable
//! inbox/outbox of remote requests, and the peer protocol v1 router.
mod error;
mod host;
mod inbound;
mod listener;
mod outbound;
mod peer_routes;
mod policy;
pub use policy::pairing_commitment;
mod ports;
mod routes;
mod service;
mod transport;

pub use error::NetworkError;
pub use host::{HostContext, NetworkSettings};
pub use inbound::InboundService;
pub use outbound::OutboundService;
pub use peer_routes::peer_routes;
pub use ports::{PeerTransport, RemoteConversationSpec, RemoteTurnRunner, TurnEvent};
pub use routes::{NetworkRouterState, network_routes};
pub use service::NetworkService;
pub use transport::HttpsPeerTransport;
