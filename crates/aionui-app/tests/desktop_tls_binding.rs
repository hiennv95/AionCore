//! While `--loopback-tls` runs, a desktop app's credentials (access token, refresh
//! token, WebSocket) work only on requests the loopback TLS listener accepted: the
//! server-injected `ViaLoopbackTls` extension. Here the two listeners are the real
//! router served twice in process, once with that extension (as the TLS listener adds
//! it) and once without (plain HTTP, and the LAN device listener, which never adds it).
//! TLS itself is covered by `loopback_tls_e2e`.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use aionui_api_types::ViaLoopbackTls;
use aionui_app::{AppConfig, AppServices, create_router};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite;

const REFUSED: &str = "DESKTOP_REQUIRES_LOOPBACK_TLS";

struct Host {
    _root: tempfile::TempDir,
    services: AppServices,
    plain: SocketAddr,
    tls: SocketAddr,
}

async fn serve(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    addr
}

async fn host(loopback_tls: bool) -> Host {
    let root = tempfile::tempdir().unwrap();
    let config = AppConfig {
        data_dir: root.path().to_path_buf(),
        work_dir: root.path().to_path_buf(),
        loopback_tls,
        ..Default::default()
    };
    let db = aionui_db::init_database_memory().await.unwrap();
    let services = AppServices::from_config(db, &config).await.unwrap();
    let router = create_router(&services).await.unwrap();
    let plain = serve(router.clone()).await;
    let tls = serve(router.layer(axum::Extension(ViaLoopbackTls))).await;
    Host {
        _root: root,
        services,
        plain,
        tls,
    }
}

async fn request(addr: SocketAddr, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut builder = client
        .request(method.parse().unwrap(), format!("http://{addr}{path}"))
        .header("x-csrf-token", "c")
        .header("cookie", "aionui-csrf-token=c");
    if let Some(token) = token {
        builder = builder.bearer_auth(token);
    }
    if let Some(body) = body {
        builder = builder.json(&body);
    }
    let resp = builder.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The desktop app's session, obtained the way the app does (bootstrap secret).
async fn desktop_session(host: &Host, addr: SocketAddr) -> (String, String) {
    let secret = std::fs::read_to_string(host._root.path().join("app-bootstrap.token")).unwrap();
    let (status, body) = request(
        addr,
        "POST",
        "/api/devices/app-session",
        None,
        Some(json!({"bootstrap_token": secret.trim(), "device_name": "Mac"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    (
        body["data"]["access_token"].as_str().unwrap().to_owned(),
        body["data"]["refresh_token"].as_str().unwrap().to_owned(),
    )
}

/// Open a WebSocket with `token` and ask it something only an authenticated, registered
/// connection answers (`subscribe-show-open` -> `show-open-request`). `Ok` means that
/// answer came back; `Err` carries what the server sent instead (a `realtime.error`, a
/// close, or nothing). An upgrade that merely stays open is not counted as accepted.
async fn websocket(addr: SocketAddr, token: &str) -> Result<(), String> {
    use futures_util::SinkExt;
    let request = tungstenite::http::Request::builder()
        .uri(format!("ws://{addr}/ws"))
        .header("Host", addr.to_string())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .header("Authorization", format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sink, mut stream) = ws.split();
    let probe = json!({"name": "subscribe-show-open", "data": {"id": "probe", "data": {}}});
    let _ = sink.send(tungstenite::Message::Text(probe.to_string().into())).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => return Err("no reply".into()),
            Ok(None) => return Err("closed".into()),
            Ok(Some(Err(error))) => return Err(error.to_string()),
            Ok(Some(Ok(tungstenite::Message::Text(text)))) => {
                let text = text.to_string();
                if text.contains("show-open-request") {
                    return Ok(());
                }
                if text.contains("realtime.error") {
                    return Err(text);
                }
            }
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => return Err(format!("close {frame:?}")),
            Ok(Some(Ok(_))) => {}
        }
    }
}

#[tokio::test]
async fn a_desktop_session_works_only_through_the_tls_listener() {
    let host = host(true).await;
    let (access, refresh) = desktop_session(&host, host.tls).await;

    // REST: accepted with the marker, refused without it.
    let (status, body) = request(host.tls, "GET", "/api/auth/user", Some(&access), None).await;
    assert_eq!(status, 200, "TLS listener: {body}");
    let (status, body) = request(host.plain, "GET", "/api/auth/user", Some(&access), None).await;
    assert_eq!((status, body["code"].clone()), (403, json!(REFUSED)), "plain: {body}");

    // Nothing the client sends stands in for the marker.
    let client = reqwest::Client::new();
    let spoofed = client
        .get(format!("http://{}/api/auth/user", host.plain))
        .bearer_auth(&access)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "127.0.0.1")
        .header("forwarded", "proto=https")
        .header("origin", format!("https://127.0.0.1:{}", host.tls.port()))
        .header("host", format!("127.0.0.1:{}", host.tls.port()))
        .header("x-aionui-via-loopback-tls", "1")
        .send()
        .await
        .unwrap();
    let status = spoofed.status().as_u16();
    let body: Value = spoofed.json().await.unwrap_or(Value::Null);
    assert_eq!(
        (status, body["code"].clone()),
        (403, json!(REFUSED)),
        "spoofed headers: {body}"
    );

    // ws-token is behind the same middleware.
    let (status, _) = request(host.plain, "GET", "/api/ws-token", Some(&access), None).await;
    assert_eq!(status, 403, "ws-token over plain");

    // Refresh over plain is refused before the grant is touched (body path, and the
    // lenient access-token form), so the same refresh token still works over TLS.
    let (status, body) = request(
        host.plain,
        "POST",
        "/api/auth/refresh",
        None,
        Some(json!({"token": refresh})),
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (403, json!(REFUSED)),
        "plain refresh: {body}"
    );
    let (status, body) = request(
        host.plain,
        "POST",
        "/api/auth/refresh",
        None,
        Some(json!({"token": access})),
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (403, json!(REFUSED)),
        "plain lenient refresh: {body}"
    );
    let client = reqwest::Client::new();
    let cookie = client
        .post(format!("http://{}/api/auth/refresh", host.plain))
        .header("x-csrf-token", "c")
        .header("cookie", format!("aionui-refresh={refresh}; aionui-csrf-token=c"))
        .send()
        .await
        .unwrap();
    let status = cookie.status().as_u16();
    let body: Value = cookie.json().await.unwrap_or(Value::Null);
    assert_eq!(
        (status, body["code"].clone()),
        (403, json!(REFUSED)),
        "plain cookie refresh: {body}"
    );
    let (status, body) = request(
        host.tls,
        "POST",
        "/api/auth/refresh",
        None,
        Some(json!({"token": refresh})),
    )
    .await;
    assert_eq!(status, 200, "TLS refresh with the same token: {body}");
    let renewed = body["token"].as_str().unwrap().to_owned();
    let renewed_refresh = body["refresh_token"].as_str().unwrap().to_owned();
    let (status, _) = request(host.tls, "GET", "/api/auth/user", Some(&renewed), None).await;
    assert_eq!(status, 200, "renewed access over TLS");
    let (status, _) = request(host.plain, "GET", "/api/auth/user", Some(&renewed), None).await;
    assert_eq!(status, 403, "renewed access over plain");

    // WebSocket: answered through the TLS listener, refused on plain.
    websocket(host.tls, &access).await.expect("TLS websocket answers");
    let refused = websocket(host.plain, &access).await.unwrap_err();
    assert!(refused.contains("REALTIME_FORBIDDEN"), "plain websocket: {refused}");
    // A refresh token is not a WebSocket credential, even over TLS.
    let refused = websocket(host.tls, &renewed_refresh).await.unwrap_err();
    assert!(
        refused.contains("REALTIME_AUTH_EXPIRED"),
        "refresh token on the TLS websocket: {refused}"
    );
}

#[tokio::test]
async fn other_sessions_keep_plain_http() {
    let host = host(true).await;
    // The desktop pairs a phone through the TLS listener; the phone uses plain HTTP.
    let tls_router = create_router(&host.services)
        .await
        .unwrap()
        .layer(axum::Extension(ViaLoopbackTls));
    let (_desktop, phone) = common::desktop_and_phone(&tls_router, host._root.path()).await;
    let (status, body) = request(host.plain, "GET", "/api/auth/user", Some(&phone), None).await;
    assert_eq!(status, 200, "paired phone over plain: {body}");
    websocket(host.plain, &phone)
        .await
        .expect("phone websocket over plain answers");

    // A device-less session (password or QR login) is not affected either.
    let owner = host.services.user_repo.get_system_user().await.unwrap().unwrap();
    let (access, _) = host
        .services
        .jwt_service
        .sign_session_pair(&owner.id, "owner", owner.session_generation, None)
        .unwrap();
    let (status, body) = request(host.plain, "GET", "/api/auth/user", Some(&access), None).await;
    assert_eq!(status, 200, "device-less session over plain: {body}");
}

#[tokio::test]
async fn without_the_flag_the_desktop_keeps_plain_http() {
    let host = host(false).await;
    let (access, refresh) = desktop_session(&host, host.plain).await;
    let (status, body) = request(host.plain, "GET", "/api/auth/user", Some(&access), None).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = request(
        host.plain,
        "POST",
        "/api/auth/refresh",
        None,
        Some(json!({"token": refresh})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    websocket(host.plain, &access)
        .await
        .expect("desktop websocket without the flag answers");
    // Even without the flag a refresh token opens no WebSocket.
    let refused = websocket(host.plain, &refresh).await.unwrap_err();
    assert!(
        refused.contains("realtime.error") || refused.starts_with("close"),
        "{refused}"
    );
}

/// A cookie may only carry a refresh token, while the legacy body path still accepts an
/// access token. Concurrent refreshes of the same access token through both channels
/// must each get their own outcome.
#[tokio::test]
async fn cookie_and_body_refreshes_of_one_token_never_share_an_outcome() {
    let host = host(false).await;
    let (access, _) = desktop_session(&host, host.plain).await;
    for _ in 0..3 {
        let cookie = async {
            reqwest::Client::new()
                .post(format!("http://{}/api/auth/refresh", host.plain))
                .header("x-csrf-token", "c")
                .header("cookie", format!("aionui-refresh={access}; aionui-csrf-token=c"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        };
        let body = request(
            host.plain,
            "POST",
            "/api/auth/refresh",
            None,
            Some(json!({"token": access})),
        );
        let (cookie, (body, _)) = tokio::join!(cookie, body);
        assert_eq!(cookie, 401, "an access token in the refresh cookie");
        assert_eq!(body, 200, "the lenient body path");
    }
}
