//! Runtime control of the mutual-TLS peer listener, so the owner can turn LAN
//! collaboration on and off from the UI without restarting the host.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aionui_peer::{PeerIdentity, serve_peer_listener, server_config};
use axum::Router;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::info;

use crate::error::NetworkError;

#[derive(Default)]
struct Running {
    task: Option<JoinHandle<()>>,
    addr: Option<SocketAddr>,
    last_error: Option<String>,
}

pub struct PeerListener {
    identity: Arc<PeerIdentity>,
    state: Mutex<Running>,
}

impl PeerListener {
    pub fn new(identity: Arc<PeerIdentity>) -> Self {
        Self {
            identity,
            state: Mutex::new(Running::default()),
        }
    }

    /// Bind and serve `router` on `addr`. Replaces a listener already running.
    pub async fn start(&self, addr: SocketAddr, router: Router) -> Result<(), NetworkError> {
        // Wait for the old task to end: its socket stays bound until the aborted
        // task is dropped, so rebinding the same port right away fails (EADDRINUSE).
        self.stop().await;
        let tls = server_config(&self.identity).map_err(|e| NetworkError::Listener(e.to_string()))?;
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!("cannot listen on {addr}: {error}");
                self.state.lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(message.clone());
                return Err(NetworkError::Listener(message));
            }
        };
        let task = tokio::spawn(serve_peer_listener(listener, tls, router));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.task = Some(task);
        state.addr = Some(addr);
        state.last_error = None;
        info!(peer_listen = %addr, host_fingerprint = %self.identity.fingerprint(), "network: peer listener ready (mutual TLS)");
        Ok(())
    }

    /// Stop accepting peer connections. Every request is authorized on its own,
    /// so connections still open cannot act beyond the current grants.
    pub async fn stop(&self) {
        if let Some(task) = self.take_running() {
            task.abort();
            // Returns once the socket is closed, so the port is free again.
            let _ = task.await;
        }
    }

    fn take_running(&self) -> Option<JoinHandle<()>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let task = state.task.take();
        if task.is_some() {
            info!(peer_listen = ?state.addr, "network: peer listener stopped");
        }
        state.addr = None;
        task
    }

    pub fn running_addr(&self) -> Option<SocketAddr> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).addr
    }

    pub fn last_error(&self) -> Option<String> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).last_error.clone()
    }
}
