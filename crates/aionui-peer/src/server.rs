//! The peer listener: mutual TLS in front of an axum router. Each request carries the
//! caller's certificate fingerprint as a [`PeerCaller`] extension; handlers authorize by it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Extension, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::identity::Fingerprint;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a connection may take to send a request's headers, idle keep-alive
/// included: a LAN host cannot hold a connection open by staying silent.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Open connections per listener; more are closed at accept.
pub const MAX_TLS_CONNECTIONS: usize = 128;

/// The authenticated peer behind a request (proven key possession, not yet authorization).
#[derive(Debug, Clone)]
pub struct PeerCaller {
    pub fingerprint: Fingerprint,
    pub remote_addr: SocketAddr,
}

/// Accept peer connections forever. Handshake failures are logged per connection and never
/// stop the listener.
pub async fn serve_peer_listener(listener: TcpListener, tls: Arc<ServerConfig>, router: Router) {
    serve_tls(listener, tls, router, true).await;
}

/// Accept server-authenticated TLS connections (no client certificate) forever, for client
/// devices that pin this host's fingerprint and authenticate with their own tokens.
pub async fn serve_device_listener(listener: TcpListener, tls: Arc<ServerConfig>, router: Router) {
    serve_tls(listener, tls, router, false).await;
}

async fn serve_tls(listener: TcpListener, tls: Arc<ServerConfig>, router: Router, mutual: bool) {
    let acceptor = TlsAcceptor::from(tls);
    // Connection tasks live in this set: dropping (aborting) the listener future
    // closes every open connection too, so turning the listener off cuts
    // keep-alive connections instead of leaving them usable.
    let mut connections = JoinSet::new();
    loop {
        let (tcp, remote_addr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "TLS listener accept failed");
                    // e.g. out of file descriptors: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        if connections.len() >= MAX_TLS_CONNECTIONS {
            debug!(%remote_addr, "TLS listener at its connection limit; closing the new connection");
            drop(tcp);
            continue;
        }
        let acceptor = acceptor.clone();
        let router = router.clone();
        connections.spawn(async move {
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    info!(%remote_addr, %error, "TLS handshake rejected");
                    return;
                }
                Err(_) => {
                    info!(%remote_addr, "TLS handshake timed out");
                    return;
                }
            };
            let router = if mutual {
                // Client certificates are mandatory here, so a completed handshake always has one.
                let Some(cert) = stream.get_ref().1.peer_certificates().and_then(|certs| certs.first()) else {
                    warn!(%remote_addr, "peer handshake completed without a client certificate");
                    return;
                };
                let caller = PeerCaller {
                    fingerprint: Fingerprint::of(cert),
                    remote_addr,
                };
                debug!(%remote_addr, peer = %caller.fingerprint.short(), "peer connection established");
                router.layer(Extension(caller))
            } else {
                router
            };
            // Same peer-address contract as the plain HTTP listener: rate limits key on it.
            let router = router.layer(Extension(axum::extract::ConnectInfo(remote_addr)));
            let service = TowerToHyperService::new(router);
            // HTTP/1.1 only (no ALPN is offered and hyper is built without http2),
            // so the header timeout runs from the first byte: a protocol-sniffing
            // builder would wait for the first bytes without any deadline.
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
            {
                debug!(%remote_addr, %error, "TLS connection closed with error");
            }
        });
    }
}
