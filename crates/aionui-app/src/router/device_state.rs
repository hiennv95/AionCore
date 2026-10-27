//! Assembly of the client-device domain (ADR-011).

use std::sync::Arc;

use aionui_db::{IDeviceRepository, SqliteDeviceRepository};
use aionui_device::{BootstrapToken, DeviceListener, DeviceRevokedHook, DeviceRouterState, DeviceService};
use aionui_peer::PeerIdentity;

use crate::services::AppServices;

/// Build the device state and write this launch's desktop bootstrap secret to
/// `<data_dir>/app-bootstrap.token`. Returns `None` (devices unavailable, the
/// legacy login keeps working) when the file cannot be written.
pub(crate) fn build_device_state(services: &AppServices) -> Option<DeviceRouterState> {
    let bootstrap = match BootstrapToken::create(&services.data_dir) {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(code = error.code(), %error, "device: bootstrap file unavailable; app sessions off");
            return None;
        }
    };
    tracing::info!(path = %bootstrap.path().display(), "device: desktop bootstrap secret written");
    // A revoked device loses its open sockets at once, not at token expiry. A
    // socket keeps the token it opened with, which may have expired since, so
    // match on the signed device id without the expiry check.
    let ws_manager = services.ws_manager.clone();
    let jwt = services.jwt_service.clone();
    let on_revoked: Arc<DeviceRevokedHook> = Arc::new(move |device_id: &str| {
        let closed = ws_manager.disconnect_tokens(
            |token| {
                jwt.decode_ignoring_expiry(token)
                    .and_then(|payload| payload.device_id)
                    .as_deref()
                    == Some(device_id)
            },
            "device revoked",
        );
        tracing::info!(%device_id, closed, "device: sockets of revoked device closed");
    });
    // Same identity as the LAN peer listener, so phones pin one host fingerprint.
    // Never in local mode: its auth layer admits anyone, and the listener is LAN-wide.
    let listener = if services.identity_mode.is_local() {
        tracing::info!("device: local identity mode; device listener off");
        None
    } else {
        match PeerIdentity::load_or_create(&services.data_dir.join("peer"), "aionx-host") {
            Ok(identity) => Some(Arc::new(DeviceListener::new(
                Arc::new(identity),
                services.data_dir.join("devices").join("listener.json"),
            ))),
            Err(error) => {
                tracing::warn!(%error, "device: host identity unavailable; device listener off");
                None
            }
        }
    };
    // Turning the listener off must cut what it let in, upgraded WebSockets included:
    // they leave its accept loop (C6). Loopback sockets (desktop app, local web) stay.
    if let Some(listener) = listener.as_ref() {
        let ws_manager = services.ws_manager.clone();
        listener.set_on_stopped(Arc::new(move || {
            let closed = ws_manager.disconnect_device_listener("device listener stopped");
            tracing::info!(closed, "device: listener stopped; its sockets closed");
        }));
    }
    let service = Arc::new(DeviceService::new(
        device_repo(services),
        services.user_repo.clone(),
        services.jwt_service.clone(),
        bootstrap,
        listener.clone(),
        Some(on_revoked),
    ));
    Some(DeviceRouterState {
        service,
        listener,
        cookies: Some(services.cookie_config.clone()),
    })
}

/// Device registry used by the auth middleware and refresh.
pub(crate) fn device_repo(services: &AppServices) -> Arc<dyn IDeviceRepository> {
    Arc::new(SqliteDeviceRepository::new(services.database.pool().clone()))
}
