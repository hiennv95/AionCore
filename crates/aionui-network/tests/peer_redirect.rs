//! Audit H22: the peer HTTPS client never follows a redirect. A pinned (or observed) peer
//! that answers 3xx towards a plain-HTTP loopback URL must not get the requester to send
//! anything there, neither a GET nor the JSON body of a POST; the pinned call still works.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aionui_api_types::PeerSubmitRequest;
use aionui_network::{HttpsPeerTransport, PeerTransport};
use aionui_peer::{PeerIdentity, device_server_config, serve_device_listener};
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use tokio::net::TcpListener;

/// Plain HTTP sink on loopback that counts every request it receives.
async fn sink() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().fallback(any(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            "sink"
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, hits)
}

/// A TLS "peer" with its own identity: every peer route redirects to `target`, except
/// `/peer/v1/shares`, which answers normally.
async fn redirecting_peer(dir: &std::path::Path, target: String) -> (String, Arc<PeerIdentity>) {
    let identity = Arc::new(PeerIdentity::load_or_create(&dir.join("peer"), "peer").unwrap());
    let redirect = move |status: StatusCode| {
        let target = target.clone();
        move || async move { (status, [(header::LOCATION, target)]).into_response() }
    };
    let app = Router::new()
        .route("/peer/v1/hello", get(redirect(StatusCode::FOUND)))
        .route("/peer/v1/requests", any(redirect(StatusCode::TEMPORARY_REDIRECT)))
        .route("/peer/v1/pairing", any(redirect(StatusCode::PERMANENT_REDIRECT)))
        .route(
            "/peer/v1/shares",
            get(|| async { axum::Json(serde_json::json!({"shares": []})) }),
        );
    let tls = device_server_config(&identity).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(serve_device_listener(listener, tls, app));
    (url, identity)
}

#[tokio::test]
async fn the_peer_client_never_follows_a_redirect() {
    let dir = tempfile::tempdir().unwrap();
    let (sink_addr, hits) = sink().await;
    let (url, peer) = redirecting_peer(dir.path(), format!("http://{sink_addr}/sink")).await;
    let me = Arc::new(PeerIdentity::load_or_create(&dir.path().join("me"), "me").unwrap());
    let transport = HttpsPeerTransport::new(me);
    let pin = peer.fingerprint().clone();

    let submit = PeerSubmitRequest {
        protocol_version: 1,
        request_id: "req-1".into(),
        share_id: "share-1".into(),
        thread_id: "thread-1".into(),
        content: "secret prompt".into(),
        deadline_at: i64::MAX,
    };
    assert!(transport.submit(&url, &pin, &submit).await.is_err(), "307 on submit");
    assert!(transport.observe(&url).await.is_err(), "302 on hello");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the plain-HTTP sink");

    // The pinned call itself still works.
    let shares = transport.list_shares(&url, &pin).await.unwrap();
    assert!(shares.shares.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
