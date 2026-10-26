//! Bootstrap layers shared by non-MCP subcommands.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use aionui_app::{AllowedOrigins, AppConfig, IdentityMode};
use aionui_db::Database;
use aionui_runtime::ShellProbeStatus;

use crate::cli::Cli;

use super::builtin_skills::materialize_builtin_skills;
use super::tracing_init::{LogGuards, init_tracing};
use super::work_dir::resolve_work_dir;
use super::{BootstrapError, BootstrapErrorCode};

/// Bounds for `--access-token-ttl-secs`: one minute to the default 30 days.
const MIN_ACCESS_TOKEN_TTL_SECS: u64 = 60;
const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Resolved environment needed by all non-MCP subcommands.
pub struct ServerEnvironment {
    /// Must be held alive for the process lifetime to flush log buffers.
    pub _log_guard: LogGuards,
    pub config: AppConfig,
    /// Built web client to serve alongside the API (`--static-dir`).
    pub static_dir: Option<PathBuf>,
    /// Interim legacy built web client to serve at /legacy/ (`--legacy-static-dir`).
    pub legacy_static_dir: Option<PathBuf>,
    /// Browser origins allowed to call the server (`--allowed-origin`).
    pub allowed_origins: Option<AllowedOrigins>,
    /// Accept only refresh tokens on every refresh path (`--strict-refresh`).
    pub strict_refresh: bool,
    /// Lifetime of newly issued access tokens (`--access-token-ttl-secs`).
    pub access_token_ttl: Option<Duration>,
    /// Close WebSockets whose token expired (`--ws-token-expiry`).
    pub ws_token_expiry: bool,
    /// Mutual-TLS peer listener address (`--peer-listen`).
    pub peer_listen: Option<std::net::SocketAddr>,
}

/// Layer 1: Logging + config resolution.
///
/// Cheap, synchronous, no IO beyond creating the log directory.
/// All subcommands that need logging and config should call this first.
pub fn init_environment(cli: &Cli, merged_path: &str) -> Result<ServerEnvironment, BootstrapError> {
    // A custom --log-dir that cannot be created must not permanently brick
    // bootstrap (AIONUI-231): init_tracing falls back to the default dir.
    let default_log_dir = cli.data_dir.join("logs");
    let log_guard = init_tracing(cli.log_dir.as_deref(), &default_log_dir, cli.log_level.as_deref())?;

    info!(
        path_segments = merged_path.split(if cfg!(windows) { ';' } else { ':' }).count(),
        path_len = merged_path.len(),
        "startup: PATH ready"
    );

    // The login-shell PATH probe runs in `main`, before `init_tracing`, so its
    // own logging goes nowhere. Replay the outcome here: a probe that timed out
    // used to leave no trace on either log sink, which made a hung startup
    // indistinguishable from a crash (AIONUI-150). Status and duration only —
    // never the PATH itself.
    match aionui_runtime::login_shell_probe_report() {
        // A timed-out probe is the AIONUI-150 signature and must be visible at
        // production's default `info` threshold.
        Some(probe) if probe.status == ShellProbeStatus::TimedOut => warn!(
            probe_status = probe.status.as_str(),
            probe_elapsed_ms = probe.elapsed_ms,
            "startup: login-shell PATH probe timed out; continuing with the inherited PATH"
        ),
        Some(probe) => info!(
            probe_status = probe.status.as_str(),
            probe_elapsed_ms = probe.elapsed_ms,
            "startup: login-shell PATH probe finished"
        ),
        None => {}
    }

    let work_dir = resolve_work_dir(cli.work_dir.clone(), &cli.data_dir);

    // SAFETY: called before any service initialization; no concurrent reads.
    unsafe {
        std::env::set_var("AIONUI_WORK_DIR", &work_dir);
    }

    let mut identity_mode: IdentityMode = cli.identity_mode.into();
    if cli.local {
        identity_mode = IdentityMode::Local;
    }
    let bootstrap_secret = std::env::var("AIONCORE_BOOTSTRAP_SECRET")
        .ok()
        .filter(|secret| !secret.is_empty());
    validate_identity_environment(identity_mode, bootstrap_secret.as_deref())?;

    let config = AppConfig {
        host: cli.host.clone(),
        port: cli.port,
        data_dir: cli.data_dir.clone(),
        work_dir,
        app_version: cli.app_version.clone(),
        local: cli.local || identity_mode.is_local(),
        identity_mode,
        bootstrap_secret,
        dump_prompts: cli.dump_prompts,
        recover_corrupted_database: cli.recover_corrupted_database,
    };
    info!(
        identity_mode = config.identity_mode.auth_label(),
        auth = if config.identity_mode.is_local() {
            "disabled"
        } else {
            "enabled"
        },
        bootstrap_secret_configured = config.bootstrap_secret.is_some(),
        "startup: identity mode resolved"
    );

    let static_dir = cli
        .static_dir
        .as_deref()
        .map(std::path::absolute)
        .transpose()
        .map_err(|error| {
            BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.static_dir",
                "invalid startup configuration",
            )
            .with_source(error)
        })?;
    if let Some(dir) = &static_dir {
        aionui_app::validate_static_dir(dir).map_err(|error| {
            BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.static_dir",
                "invalid startup configuration",
            )
            .with_source(error)
        })?;
        info!(static_dir = %dir.display(), "startup: static web client enabled");
    }

    let legacy_static_dir = cli
        .legacy_static_dir
        .as_deref()
        .map(std::path::absolute)
        .transpose()
        .map_err(|error| {
            BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.legacy_static_dir",
                "invalid startup configuration",
            )
            .with_source(error)
        })?;
    if let Some(dir) = &legacy_static_dir {
        aionui_app::validate_static_dir(dir).map_err(|error| {
            BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.legacy_static_dir",
                "invalid startup configuration",
            )
            .with_source(error)
        })?;
        info!(legacy_static_dir = %dir.display(), "startup: legacy static web client enabled at /legacy/");
    }

    let allowed_origins = if cli.allowed_origins.is_empty() {
        None
    } else {
        let origins = AllowedOrigins::parse(&cli.allowed_origins).map_err(|error| {
            BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.allowed_origin",
                "invalid startup configuration",
            )
            .with_source(error)
        })?;
        info!(allowed_origins = ?origins.sorted(), "startup: browser origin allowlist enabled");
        Some(origins)
    };

    let access_token_ttl = cli
        .access_token_ttl_secs
        .map(|secs| {
            if (MIN_ACCESS_TOKEN_TTL_SECS..=MAX_ACCESS_TOKEN_TTL_SECS).contains(&secs) {
                Ok(Duration::from_secs(secs))
            } else {
                Err(BootstrapError::new(
                    BootstrapErrorCode::ConfigInvalid,
                    "config.access_token_ttl",
                    "invalid startup configuration",
                )
                .with_field("access_token_ttl_secs", secs.to_string()))
            }
        })
        .transpose()?;
    if cli.strict_refresh || access_token_ttl.is_some() || cli.ws_token_expiry {
        info!(
            strict_refresh = cli.strict_refresh,
            access_token_ttl_secs = access_token_ttl.map(|ttl| ttl.as_secs()),
            ws_token_expiry = cli.ws_token_expiry,
            "startup: token policy overrides enabled"
        );
    }

    Ok(ServerEnvironment {
        _log_guard: log_guard,
        config,
        static_dir,
        legacy_static_dir,
        allowed_origins,
        strict_refresh: cli.strict_refresh,
        access_token_ttl,
        ws_token_expiry: cli.ws_token_expiry,
        peer_listen: cli.peer_listen,
    })
}

fn validate_identity_environment(
    identity_mode: IdentityMode,
    bootstrap_secret: Option<&str>,
) -> Result<(), BootstrapError> {
    if identity_mode == IdentityMode::AionPro && bootstrap_secret.is_none() {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.identity_mode",
            "AionPro identity mode requires AIONCORE_BOOTSTRAP_SECRET",
        ));
    }

    Ok(())
}

/// Layer 2: Materialize builtin skills + initialize the database.
///
/// Requires only `data_dir`. Subcommands that need persistent state
/// (database, skill files) should call this after `init_environment`.
pub async fn init_data_layer(config: &AppConfig) -> Result<Database, BootstrapError> {
    let boot = Instant::now();

    materialize_builtin_skills(&config.data_dir).await.map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.builtin_skills",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("dataDir", config.data_dir.display().to_string())
    })?;
    info!(
        elapsed_ms = boot.elapsed().as_millis(),
        "startup: builtin skills materialized"
    );

    let db_path = config.database_path();
    aionui_db::maybe_copy_legacy_database(&db_path).map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.legacy_db",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("databasePath", db_path.display().to_string())
    })?;
    info!("Initializing database at {}", db_path.display());
    let database = aionui_db::init_database_staged_with_options(
        &db_path,
        aionui_db::DatabaseInitOptions {
            recover_corrupted_database: config.recover_corrupted_database,
        },
    )
    .await
    .map_err(|e| database_init_bootstrap_error(e, &db_path))?;
    info!(elapsed_ms = boot.elapsed().as_millis(), "startup: database initialized");

    Ok(database)
}

/// Map a database init failure to the bootstrap boundary error.
///
/// For the downgrade stage (`database.newer_than_app`) the stderr line carries
/// both migration versions so the host and production logs can tell the user
/// which release the database requires, without exposing the raw source error.
fn database_init_bootstrap_error(error: aionui_db::DatabaseInitError, db_path: &std::path::Path) -> BootstrapError {
    let stage = error.stage();
    let source = error.into_source();
    let mut bootstrap_error = BootstrapError::new(
        BootstrapErrorCode::DataInitFailed,
        stage,
        "failed to initialize application data",
    )
    .with_field("databasePath", db_path.display().to_string());
    if let Some(db_version) = source.missing_migration_version() {
        bootstrap_error = bootstrap_error.with_field("dbMigrationVersion", db_version.to_string());
        if let Some(app_version) = aionui_db::latest_known_migration_version() {
            bootstrap_error = bootstrap_error.with_field("appMigrationVersion", app_version.to_string());
        }
    }
    bootstrap_error.with_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.migration",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::VersionMismatch(42)),
        );

        assert_eq!(err.stage(), "database.migration");
    }

    #[test]
    fn database_schema_repair_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.schema_repair",
            aionui_db::DbError::Init("repair failed".into()),
        );

        assert_eq!(err.stage(), "database.schema_repair");
    }

    #[test]
    fn database_recoverable_corruption_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.recoverable_corruption",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::ExecuteMigration(
                sqlx::Error::Protocol("database disk image is malformed".into()),
                13,
            )),
        );

        assert_eq!(err.stage(), "database.recoverable_corruption");
    }

    #[test]
    fn newer_than_app_stage_carries_migration_versions_on_stderr() {
        let err = aionui_db::DatabaseInitError::new(
            aionui_db::DATABASE_NEWER_THAN_APP_STAGE,
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::VersionMissing(39)),
        );

        let bootstrap = database_init_bootstrap_error(err, std::path::Path::new("/db/path/aionui-backend.db"));
        let line = bootstrap.stderr_line();
        assert!(
            line.starts_with("BOOTSTRAP_DATA_INIT_FAILED stage=database.newer_than_app"),
            "{line}"
        );
        assert!(line.contains("dbMigrationVersion=39"), "{line}");
        let app_version = aionui_db::latest_known_migration_version().unwrap();
        assert!(line.contains(&format!("appMigrationVersion={app_version}")), "{line}");
        // The raw sqlx message stays out of stderr (boundary contract).
        assert!(!line.contains("previously applied"), "{line}");
    }

    #[test]
    fn generic_database_failures_do_not_carry_migration_versions() {
        let err = aionui_db::DatabaseInitError::new(
            "database.migration",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::VersionMismatch(7)),
        );

        let bootstrap = database_init_bootstrap_error(err, std::path::Path::new("/db/path/aionui-backend.db"));
        let line = bootstrap.stderr_line();
        assert!(
            line.starts_with("BOOTSTRAP_DATA_INIT_FAILED stage=database.migration"),
            "{line}"
        );
        assert!(!line.contains("MigrationVersion"), "{line}");
    }

    #[test]
    fn aionpro_identity_requires_bootstrap_secret() {
        let err = validate_identity_environment(IdentityMode::AionPro, None)
            .expect_err("AionPro startup must require bootstrap secret");

        assert_eq!(err.code(), BootstrapErrorCode::ConfigInvalid);
        assert_eq!(err.stage(), "config.identity_mode");
    }

    #[test]
    fn aionpro_identity_accepts_bootstrap_secret() {
        validate_identity_environment(IdentityMode::AionPro, Some("secret"))
            .expect("AionPro startup should accept configured bootstrap secret");
    }

    #[test]
    fn non_aionpro_identity_does_not_require_bootstrap_secret() {
        validate_identity_environment(IdentityMode::WebUi, None)
            .expect("WebUI startup should not require bootstrap secret");
        validate_identity_environment(IdentityMode::Local, None)
            .expect("local startup should not require bootstrap secret");
    }
}
