#![warn(clippy::disallowed_types)]

//! Client devices without an account login (ADR-011): desktop app bootstrap,
//! "connect device" pairing, device list and revocation.
mod bootstrap;
mod error;
mod listener;
mod loopback;
mod pairing;
mod routes;
mod secret;
mod service;

pub use bootstrap::{BOOTSTRAP_FILE_NAME, BootstrapToken};
pub use error::DeviceError;
pub use listener::{DEFAULT_DEVICE_PORT, DeviceListener, no_desktop_bootstrap};
pub use loopback::{
    IDENTITY_METADATA_FILE, LoopbackTlsListener, publish_identity_metadata, withdraw_identity_metadata,
};
pub use pairing::{MAX_OPEN_PAIRINGS, PAIRING_TTL_MS};
pub use routes::{DeviceRouterState, device_bootstrap_routes, device_owner_routes, device_public_routes};
pub use service::{Caller, DeviceRevokedHook, DeviceService};
