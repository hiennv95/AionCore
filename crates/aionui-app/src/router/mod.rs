//! HTTP router assembly for the application.

mod antigravity_hook;
mod clipboard_writer;
mod fs_monitor;
mod health;
mod item_revealer;
mod origin_guard;
mod routes;
mod runtime_team_tools;
mod scm_monitor;
mod state;
mod static_web;
mod system_file_opener;
mod team_capability_resolver;
mod team_conversation_adapters;
mod trace;

pub use origin_guard::{AllowedOrigins, InvalidOriginError, with_origin_guard};
pub use routes::{
    RouterRuntime, create_router, create_router_with_all_state, create_router_with_runtime, create_router_with_states,
};
pub use state::{
    ChannelOrchestratorComponents, ModuleStates, RouterBuildError, build_assistant_state, build_conversation_state,
    build_extension_states, build_module_states, build_ws_state,
};
pub use static_web::{StaticDirError, validate_static_dir, with_static_web};
