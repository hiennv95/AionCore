//! Audit H14: the desktop bootstrap (`/api/devices/app-session` and `/api/devices/host-proof`)
//! is for the desktop app on loopback only. The LAN device listener serves the same app router
//! over TLS, and refuses both routes there; every other route stays served. The real app router
//! is attached to a real `DeviceListener` and called over pinned TLS.

mod common;

use std::sync::Arc;

use aionui_api_types::UpdateDeviceListenerRequest;
use aionui_device::DeviceListener;
use aionui_peer::{PeerIdentity, ServerPin, client_config};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_skill_paths};

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn loopback_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn the_device_listener_never_serves_the_desktop_bootstrap() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _services, _) = build_app_with_skill_paths(tmp.path()).await;
    let bootstrap = std::fs::read_to_string(tmp.path().join("app-bootstrap.token")).unwrap();
    let session_body = json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"});

    let identity = Arc::new(PeerIdentity::load_or_create(&tmp.path().join("listener-peer"), "host").unwrap());
    let listener = DeviceListener::new(identity.clone(), tmp.path().join("devices/listener.json"));
    listener.attach(app.clone()).await.unwrap();
    let port = free_port();
    listener
        .update(UpdateDeviceListenerRequest {
            enabled: Some(true),
            port: Some(port),
        })
        .await
        .unwrap();
    let phone = PeerIdentity::load_or_create(&tmp.path().join("phone"), "phone").unwrap();
    let tls = client_config(&phone, ServerPin::Expect(identity.fingerprint().clone())).unwrap();
    let lan = reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .build()
        .unwrap();
    let base = format!("https://127.0.0.1:{port}");

    // Over the device listener: both bootstrap routes are refused, with the right secret.
    for (path, body) in [
        ("/api/devices/app-session", session_body.clone()),
        ("/api/devices/host-proof", json!({"nonce": NONCE})),
        ("/api/devices/app-session/", session_body.clone()),
    ] {
        let resp = lan.post(format!("{base}{path}")).json(&body).send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND, "LAN {path}: {text}");
        assert!(
            !text.contains("access_token") && !text.contains("proof"),
            "LAN {path}: {text}"
        );
    }
    // Other routes are still served there.
    let resp = lan.get(format!("{base}/api/auth/status")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "LAN keeps serving the app");

    // On loopback the desktop app still bootstraps.
    let resp = app
        .clone()
        .oneshot(loopback_post("/api/devices/host-proof", json!({"nonce": NONCE})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let proof = body_json(resp).await;
    assert!(
        proof["data"]["proof"].as_str().is_some_and(|p| !p.is_empty()),
        "{proof}"
    );
    let resp = app
        .oneshot(loopback_post("/api/devices/app-session", session_body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let session = body_json(resp).await;
    assert!(session["data"]["access_token"].as_str().is_some(), "{session}");

    listener
        .update(UpdateDeviceListenerRequest {
            enabled: Some(false),
            port: None,
        })
        .await
        .unwrap();
}
