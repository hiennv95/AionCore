//! Health check endpoint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aionui_db::{Database, SqlitePool};
use axum::Json;
use axum::extract::State;
use serde::Serialize;

/// A health probe must answer fast even when the database hangs.
const DB_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Last probe result, so a polled failing probe logs on the transition only.
static DATABASE_DEGRADED: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
pub(super) struct HealthResponse {
    /// `ok`, or `degraded` when a subsystem check fails. The HTTP status stays 200
    /// so "is the process up" probes keep working (Jev 028, degraded-200).
    status: &'static str,
    version: &'static str,
    build_time: &'static str,
    checks: HealthChecks,
}

#[derive(Serialize)]
struct HealthChecks {
    database: &'static str,
}

pub(super) async fn health_check(State(pool): State<SqlitePool>) -> Json<HealthResponse> {
    let database_ok = matches!(
        tokio::time::timeout(DB_PROBE_TIMEOUT, Database::ping(&pool)).await,
        Ok(true)
    );
    let was_degraded = DATABASE_DEGRADED.swap(!database_ok, Ordering::Relaxed);
    if !database_ok && !was_degraded {
        tracing::warn!("health: database probe failed; reporting degraded");
    } else if database_ok && was_degraded {
        tracing::info!("health: database probe recovered");
    }
    Json(HealthResponse {
        status: if database_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        build_time: env!("BUILD_TIME"),
        checks: HealthChecks {
            database: if database_ok { "ok" } else { "error" },
        },
    })
}
