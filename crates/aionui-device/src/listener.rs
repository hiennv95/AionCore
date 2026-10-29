//! Device listener (ADR-011 §4): HTTPS with this host's existing identity for
//! paired phones and browsers on other machines. Off by default; the owner
//! turns it on. Serves the same router as the loopback listener, behind a
//! same-origin guard.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use aionui_api_types::{DeviceListenerInfo, DeviceListenerStatus, UpdateDeviceListenerRequest};
use aionui_peer::{PeerIdentity, device_server_config, serve_device_listener};
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::info;

use crate::error::DeviceError;

pub const DEFAULT_DEVICE_PORT: u16 = 25821;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Settings {
    enabled: bool,
    port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_DEVICE_PORT,
        }
    }
}

#[derive(Default)]
struct Running {
    task: Option<JoinHandle<()>>,
    last_error: Option<String>,
}

pub struct DeviceListener {
    identity: Arc<PeerIdentity>,
    settings_path: PathBuf,
    settings: Mutex<Settings>,
    running: Mutex<Running>,
    router: OnceLock<Router>,
    /// Run after the accept loop is stopped: upgraded WebSockets live outside it (C6).
    on_stopped: OnceLock<Arc<dyn Fn() + Send + Sync>>,
}

/// Best-effort primary LAN address: the source address the OS would use to
/// reach an outside network (no packet is sent). Empty when offline.
fn lan_addresses() -> Vec<String> {
    let probe = || -> Option<IpAddr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
        Some(socket.local_addr().ok()?.ip())
    };
    probe()
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| vec![ip.to_string()])
        .unwrap_or_default()
}

/// Browsers must call the listener from its own origin (`https://<Host>`).
/// Requests without `Origin` (native apps, top-level navigations) pass.
async fn same_origin_only(request: Request, next: Next) -> Response {
    let origin = request.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = request.headers().get(header::HOST).and_then(|v| v.to_str().ok());
    if let Some(origin) = origin
        && host.is_none_or(|host| !origin.eq_ignore_ascii_case(&format!("https://{host}")))
    {
        tracing::info!(origin, "device listener: cross-origin request rejected");
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    next.run(request).await
}

/// The desktop bootstrap (session from the bootstrap secret, and the host proof) is for
/// the desktop app on loopback only: the LAN has no reason to reach it (audit H14).
/// With `--loopback-tls` the plain HTTP listener refuses it too, so the secret and
/// the session it buys only travel over TLS.
pub async fn no_desktop_bootstrap(request: Request, next: Next) -> Response {
    let path = request.uri().path().trim_end_matches('/');
    if path == "/api/devices/app-session" || path == "/api/devices/host-proof" {
        tracing::info!(path, "device listener: desktop bootstrap refused");
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    next.run(request).await
}

/// Every cookie issued over this TLS listener is `Secure`, so a browser never
/// replays the owner session over plain HTTP to another port on this host.
pub(crate) async fn secure_cookies(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let cookies: Vec<_> = headers.get_all(header::SET_COOKIE).iter().cloned().collect();
    if cookies.is_empty() {
        return response;
    }
    headers.remove(header::SET_COOKIE);
    for cookie in cookies {
        let secured = match cookie.to_str() {
            Ok(text) if !text.to_ascii_lowercase().contains("; secure") => {
                HeaderValue::from_str(&format!("{text}; Secure")).unwrap_or(cookie)
            }
            _ => cookie,
        };
        headers.append(header::SET_COOKIE, secured);
    }
    response
}

impl DeviceListener {
    /// Settings live in `<settings_path>`; a missing or unreadable file means "off".
    pub fn new(identity: Arc<PeerIdentity>, settings_path: PathBuf) -> Self {
        let settings = std::fs::read(&settings_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            identity,
            settings_path,
            settings: Mutex::new(settings),
            running: Mutex::new(Running::default()),
            router: OnceLock::new(),
            on_stopped: OnceLock::new(),
        }
    }

    /// Set once: called whenever the listener stops, to close what its accept loop does not own.
    pub fn set_on_stopped(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        let _ = self.on_stopped.set(hook);
    }

    fn settings(&self) -> Settings {
        *self.settings.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Give the listener the app router once it is built, and start it if enabled.
    pub async fn attach(&self, router: Router) -> Result<(), DeviceError> {
        let _ = self.router.set(
            router
                .layer(middleware::from_fn(no_desktop_bootstrap))
                .layer(middleware::from_fn(same_origin_only))
                .layer(middleware::from_fn(secure_cookies)),
        );
        if self.settings().enabled {
            self.start().await?;
        }
        Ok(())
    }

    async fn start(&self) -> Result<(), DeviceError> {
        self.stop();
        let Some(router) = self.router.get().cloned() else {
            return Err(DeviceError::Internal(
                "device listener started before the router".into(),
            ));
        };
        let tls = device_server_config(&self.identity).map_err(|e| DeviceError::Internal(e.to_string()))?;
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.settings().port));
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!("cannot listen on {addr}: {error}");
                self.running.lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(message.clone());
                return Err(DeviceError::InvalidRequest(message));
            }
        };
        let task = tokio::spawn(serve_device_listener(listener, tls, router));
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        running.task = Some(task);
        running.last_error = None;
        info!(device_listen = %addr, host_fingerprint = %self.identity.fingerprint(), "device: listener ready (TLS)");
        Ok(())
    }

    /// Stop accepting device connections and drop open ones.
    pub fn stop(&self) {
        if let Some(task) = self.running.lock().unwrap_or_else(|e| e.into_inner()).task.take() {
            task.abort();
            info!("device: listener stopped");
            if let Some(hook) = self.on_stopped.get() {
                hook();
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    /// How devices reach this host, or `None` while off.
    pub fn info(&self) -> Option<DeviceListenerInfo> {
        self.is_running().then(|| DeviceListenerInfo {
            port: self.settings().port,
            fingerprint: self.identity.fingerprint().as_str().to_owned(),
            addresses: lan_addresses(),
        })
    }

    pub fn status(&self) -> DeviceListenerStatus {
        let settings = self.settings();
        DeviceListenerStatus {
            enabled: settings.enabled,
            port: settings.port,
            running: self.is_running(),
            fingerprint: self.identity.fingerprint().as_str().to_owned(),
            addresses: lan_addresses(),
            last_error: self
                .running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last_error
                .clone(),
        }
    }

    pub async fn update(&self, req: UpdateDeviceListenerRequest) -> Result<DeviceListenerStatus, DeviceError> {
        let mut next = self.settings();
        if let Some(port) = req.port {
            if port < 1024 {
                return Err(DeviceError::InvalidRequest("port must be 1024-65535".into()));
            }
            next.port = port;
        }
        if let Some(enabled) = req.enabled {
            next.enabled = enabled;
        }
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| DeviceError::Internal(e.to_string()))?;
        if let Some(dir) = self.settings_path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| DeviceError::Internal(e.to_string()))?;
        }
        std::fs::write(&self.settings_path, bytes).map_err(|e| DeviceError::Internal(e.to_string()))?;
        *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = next;
        if next.enabled {
            self.start().await?;
        } else {
            self.stop();
        }
        info!(
            enabled = next.enabled,
            port = next.port,
            "device: listener setting changed"
        );
        Ok(self.status())
    }
}
