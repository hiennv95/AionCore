//! Process-level bootstrap helpers for the binary.
//!
//! These are *not* subcommands — they are layered initialization steps
//! (logging, work_dir resolution, builtin-skill materialization, database
//! init) that subcommands compose to start the application.

mod builtin_skills;
mod environment;
mod error;
mod instance_guard;
mod log_retention;
mod panic_hook;
mod parent_exit;
mod private_data_dir;
mod shutdown_watchdog;
mod tracing_init;
mod work_dir;

pub use environment::{ServerEnvironment, init_data_layer, init_environment};
pub(crate) use error::{BootstrapError, BootstrapErrorCode};
pub(crate) use instance_guard::wait_for_instance_guard;
pub(crate) use panic_hook::install_panic_hook;
pub(crate) use parent_exit::{ParentExitSignal, parent_exit_signal};
pub(crate) use private_data_dir::{secure_data_dir, secure_database_files};
pub(crate) use shutdown_watchdog::ShutdownWatchdog;
