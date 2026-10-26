//! The device listener over real TLS on loopback: pinned fingerprint, same-origin
//! guard, on/off, persisted settings.

use std::sync::Arc;

use aionui_api_types::UpdateDeviceListenerRequest;
use aionui_device::DeviceListener;
use aionui_peer::{PeerIdentity, ServerPin, client_config};
use axum::Router;
use axum::routing::get;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A client that trusts only this host's fingerprint (what the phone does after
/// scanning the QR code). The client's own certificate is ignored by the server.
fn pinned_client(host: &PeerIdentity, dir: &std::path::Path) -> reqwest::Client {
    let me = PeerIdentity::load_or_create(&dir.join("phone"), "phone").unwrap();
    let tls = client_config(&me, ServerPin::Expect(host.fingerprint().clone())).unwrap();
    reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .build()
        .unwrap()
}

#[tokio::test]
async fn listener_serves_tls_guards_origin_and_persists_settings() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(PeerIdentity::load_or_create(&dir.path().join("peer"), "host").unwrap());
    let settings = dir.path().join("devices/listener.json");
    let listener = DeviceListener::new(identity.clone(), settings.clone());
    listener
        .attach(Router::new().route("/api/ping", get(|| async { "pong" })).route(
            "/api/cookie",
            get(|| async {
                (
                    [("set-cookie", "aionui-session=x; Path=/; HttpOnly; SameSite=Lax")],
                    "ok",
                )
            }),
        ))
        .await
        .unwrap();
    assert!(!listener.status().running, "off by default");
    assert!(listener.info().is_none());

    let port = free_port();
    let status = listener
        .update(UpdateDeviceListenerRequest {
            enabled: Some(true),
            port: Some(port),
        })
        .await
        .unwrap();
    assert!(status.running);
    assert_eq!(listener.info().unwrap().fingerprint, identity.fingerprint().as_str());

    let client = pinned_client(&identity, dir.path());
    let url = format!("https://127.0.0.1:{port}/api/ping");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "pong");

    let resp = client
        .get(&url)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .get(&url)
        .header("origin", format!("https://127.0.0.1:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Cookies issued over TLS are Secure, so browsers never send them over plain HTTP.
    let resp = client
        .get(format!("https://127.0.0.1:{port}/api/cookie"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers()["set-cookie"],
        "aionui-session=x; Path=/; HttpOnly; SameSite=Lax; Secure"
    );

    // A client pinned to another fingerprint cannot connect.
    let other = PeerIdentity::load_or_create(&dir.path().join("other"), "other").unwrap();
    let wrong = pinned_client(&other, dir.path());
    assert!(wrong.get(&url).send().await.is_err());

    // Settings survive a restart; turning it off closes the port.
    let reloaded = DeviceListener::new(identity.clone(), settings);
    assert!(reloaded.status().enabled);
    assert_eq!(reloaded.status().port, port);
    listener
        .update(UpdateDeviceListenerRequest {
            enabled: Some(false),
            port: None,
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(client.get(&url).send().await.is_err());

    let err = listener
        .update(UpdateDeviceListenerRequest {
            enabled: None,
            port: Some(80),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), "INVALID_REQUEST");
}
