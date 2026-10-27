#![warn(clippy::disallowed_types)]

//! Application crate: assembles all domain crates into an Axum server with DI and middleware.
//!
//! This file is a public façade — it only re-exports symbols defined in
//! submodules. All logic lives in the modules below.

mod config;
mod router;
mod services;

pub use config::{AppConfig, IdentityMode, derive_encryption_key};
pub use router::{
    AllowedHosts, AllowedOrigins, ChannelOrchestratorComponents, InvalidOriginError, ModuleStates, RouterBuildError,
    RouterRuntime, StaticDirError, build_assistant_state, build_conversation_state, build_extension_states,
    build_module_states, build_ws_state, create_router, create_router_with_all_state, create_router_with_runtime,
    create_router_with_states, validate_static_dir, with_host_guard, with_origin_guard, with_static_web,
    with_static_web_clients,
};
pub use services::AppServices;
