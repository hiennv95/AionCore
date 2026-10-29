//! Host-filesystem authority by session kind (ADR-013, Jev 053 first slice): the desktop
//! app and local mode may use host-file routes and send `Local` file refs; a paired
//! phone, a device-less password session and the agent helper get 403 `FS_OWNER_ONLY`.

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_mock_agents_at, desktop_and_phone, json_with_token, setup_and_login};

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), body_json(resp).await)
}

/// A session minted before policy B (Jev 057): no device_id. A password login now
/// yields a device-bound `browser` session instead.
async fn deviceless_token(services: &aionui_app::AppServices) -> String {
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap();
    services
        .jwt_service
        .sign_session_pair(&owner.id, "admin", owner.session_generation, None)
        .unwrap()
        .0
}

fn image_request(path: &str) -> Value {
    json!({ "path": path })
}

#[tokio::test]
async fn host_file_routes_follow_the_session_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = build_app_with_mock_agents_at(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let (browser, csrf) = setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let deviceless = deviceless_token(&services).await;
    let image = tmp.path().join("pixel.png");
    std::fs::write(&image, b"\x89PNG\r\n\x1a\n").unwrap();
    let image = image.to_string_lossy().into_owned();
    let refused = (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"));

    let (status, resp) = send(
        &app,
        json_with_token("POST", "/api/fs/image-base64", image_request(&image), &desktop, "c"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "desktop: {resp}");

    let (status, resp) = send(
        &app,
        json_with_token("POST", "/api/fs/image-base64", image_request(&image), &phone, "c"),
    )
    .await;
    assert_eq!((status, resp["code"].clone()), refused, "paired phone: {resp}");

    let mut conversation = String::new();
    for (token, who) in [(&deviceless, "device-less"), (&browser, "password browser")] {
        let (status, resp) = send(
            &app,
            json_with_token("POST", "/api/fs/image-base64", image_request(&image), token, &csrf),
        )
        .await;
        assert_eq!((status, resp["code"].clone()), refused, "{who}: {resp}");

        // Both restricted kinds may still use ordinary account routes...
        let (status, resp) = send(
            &app,
            json_with_token(
                "POST",
                "/api/conversations",
                json!({"type": "acp", "name": "deviceless chat", "extra": {"backend": "gemini"}}),
                token,
                &csrf,
            ),
        )
        .await;
        assert!(status.is_success(), "{who} create chat: {status} {resp}");
        conversation = resp["data"]["id"].as_str().unwrap().to_owned();

        // ...but cannot send a `Local` host file ref, existing or not.
        let body = json!({"content": "read this", "files": [{"kind": "local", "path": image}]});
        let (status, resp) = send(
            &app,
            json_with_token(
                "POST",
                &format!("/api/conversations/{conversation}/messages"),
                body,
                token,
                &csrf,
            ),
        )
        .await;
        assert_eq!((status, resp["code"].clone()), refused, "{who} local ref: {resp}");
    }

    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        &conversation,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/fs/image-base64")
        .header("content-type", "application/json")
        .header("x-aionui-runtime-token", helper.token.as_str())
        .header("x-aionui-user-id", owner.as_str())
        .header("x-aionui-conversation-id", conversation.as_str())
        .body(Body::from(image_request(&image).to_string()))
        .unwrap();
    let (status, resp) = send(&app, req).await;
    assert_eq!((status, resp["code"].clone()), refused, "helper: {resp}");

    // C11: the cron resume sweep is internal; the agent helper cannot trigger it by
    // setting the client-chosen `x-aionui-internal` header. The desktop still can.
    let helper_resume = Request::builder()
        .method("POST")
        .uri("/api/cron/internal/system-resume")
        .header("content-type", "application/json")
        .header("x-aionui-internal", "1")
        .header("x-aionui-runtime-token", helper.token.as_str())
        .header("x-aionui-user-id", owner.as_str())
        .header("x-aionui-conversation-id", conversation.as_str())
        .body(Body::from("{}"))
        .unwrap();
    let (status, resp) = send(&app, helper_resume).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "helper resume: {resp}");
    let desktop_resume = Request::builder()
        .method("POST")
        .uri("/api/cron/internal/system-resume")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {desktop}"))
        .header("x-csrf-token", "c")
        .header("cookie", "aionui-csrf-token=c")
        .header("x-aionui-internal", "1")
        .body(Body::from("{}"))
        .unwrap();
    let (status, resp) = send(&app, desktop_resume).await;
    assert_eq!(status, StatusCode::OK, "desktop resume: {resp}");
}

#[tokio::test]
async fn local_mode_keeps_host_file_authority() {
    let tmp = tempfile::tempdir().unwrap();
    let image = tmp.path().join("pixel.png");
    std::fs::write(&image, b"\x89PNG\r\n\x1a\n").unwrap();
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        local: true,
        data_dir: tmp.path().to_path_buf(),
        work_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();
    let app = aionui_app::create_router(&services).await.expect("build router");

    let req = Request::builder()
        .method("POST")
        .uri("/api/fs/image-base64")
        .header("content-type", "application/json")
        .header("x-csrf-token", "c")
        .header("cookie", "aionui-csrf-token=c")
        .body(Body::from(image_request(&image.to_string_lossy()).to_string()))
        .unwrap();
    let (status, resp) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "local mode: {resp}");
    services.database.close().await;
}

/// Jev 053: device and LAN management follow the same split — the desktop app manages,
/// a device-less password session is refused like a paired phone.
#[tokio::test]
async fn device_and_lan_management_follow_the_session_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = build_app_with_mock_agents_at(tmp.path()).await;
    let (desktop, _phone) = desktop_and_phone(&app, tmp.path()).await;
    let (browser, csrf) = setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let deviceless = deviceless_token(&services).await;

    for (token, who) in [(&deviceless, "device-less"), (&browser, "password browser")] {
        let (status, resp) = send(
            &app,
            json_with_token("POST", "/api/devices/pairings", json!({}), token, &csrf),
        )
        .await;
        assert_eq!(
            (status, resp["code"].clone()),
            (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY")),
            "{who} pairing: {resp}"
        );
        let (status, resp) = send(
            &app,
            json_with_token(
                "PUT",
                "/api/network/status",
                json!({"display_name": "Owner Mac"}),
                token,
                &csrf,
            ),
        )
        .await;
        assert_eq!(
            (status, resp["code"].clone()),
            (StatusCode::FORBIDDEN, json!("NETWORK_OWNER_ONLY")),
            "{who} LAN settings: {resp}"
        );
    }
    let (status, resp) = send(
        &app,
        json_with_token("POST", "/api/devices/pairings", json!({}), &desktop, "c"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "desktop pairing: {resp}");
    assert!(resp["data"]["secret"].is_string(), "desktop pairing: {resp}");

    let settings = json!({"display_name": "Owner Mac"});
    let (status, resp) = send(
        &app,
        json_with_token("PUT", "/api/network/status", settings, &desktop, "c"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "desktop LAN settings: {resp}");
}

/// H6/H7: opening a URL on the host and listing host skill config dirs are desktop
/// effects; a paired phone and a device-less session are refused. The harmless tool
/// probe (a bool) stays open. Desktop gets past the gate (an invalid scheme returns
/// 400, so no browser is opened).
#[tokio::test]
async fn host_open_and_config_probes_follow_the_session_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = build_app_with_mock_agents_at(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let (browser, csrf) = setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let deviceless = deviceless_token(&services).await;
    let refused = (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"));
    let open = json!({"url": "ftp://example.com"});

    for (token, csrf, who) in [
        (&phone, "c", "phone"),
        (&deviceless, csrf.as_str(), "device-less"),
        (&browser, csrf.as_str(), "password browser"),
    ] {
        let (status, resp) = send(
            &app,
            json_with_token("POST", "/api/shell/open-external", open.clone(), token, csrf),
        )
        .await;
        assert_eq!((status, resp["code"].clone()), refused, "{who} open-external: {resp}");
        for uri in ["/api/skills/detect-paths", "/api/skills/detect-external"] {
            let (status, resp) = send(&app, json_with_token("GET", uri, json!({}), token, csrf)).await;
            assert_eq!((status, resp["code"].clone()), refused, "{who} {uri}: {resp}");
        }
        let (status, resp) = send(
            &app,
            json_with_token(
                "POST",
                "/api/shell/check-tool-installed",
                json!({"tool": "vscode"}),
                token,
                csrf,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{who} check-tool-installed: {resp}");
    }

    let (status, resp) = send(
        &app,
        json_with_token("POST", "/api/shell/open-external", open, &desktop, "c"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "desktop open-external: {resp}");
    for uri in ["/api/skills/detect-paths", "/api/skills/detect-external"] {
        let (status, resp) = send(&app, json_with_token("GET", uri, json!({}), &desktop, "c")).await;
        assert_eq!(status, StatusCode::OK, "desktop {uri}: {resp}");
    }
}
