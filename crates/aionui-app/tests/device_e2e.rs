//! ADR-011 through the real app router: desktop bootstrap file, CSRF-exempt
//! handshake endpoints, owner endpoints behind auth + CSRF, device revocation.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};

use common::{body_json, build_app_with_skill_paths, delete_with_token, get_with_token, json_with_token};

fn public_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    // No cookie, no CSRF header: native clients and first contact have neither.
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn desktop_app_bootstraps_from_the_data_dir_file_without_login() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();

    let resp = app
        .clone()
        .oneshot(public_post(
            "/api/devices/app-session",
            json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let session = body_json(resp).await["data"].clone();
    let token = session["access_token"].as_str().unwrap().to_owned();

    // The device session reaches ordinary owner APIs (no account was created).
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/devices", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let devices = body_json(resp).await;
    assert_eq!(devices["data"][0]["kind"], "desktop_app");
    assert_eq!(devices["data"][0]["current"], true);
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/conversations?limit=1", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Owner mutations still require CSRF: without the double-submit pair → 403.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/devices/pairings")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/devices/pairings",
            json!({}),
            &token,
            "csrf-1",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Revoking itself ends the session.
    let device_id = session["device_id"].as_str().unwrap();
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/devices/{device_id}/revoke"),
            json!({}),
            &token,
            "csrf-1",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/devices", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["code"], "DEVICE_REVOKED");
}

#[tokio::test]
async fn bad_bootstrap_and_unknown_pairing_are_refused_without_csrf_noise() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let resp = app
        .clone()
        .oneshot(public_post("/api/devices/app-session", json!({"bootstrap_token": "x"})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["code"], "BOOTSTRAP_INVALID");
    let resp = app
        .clone()
        .oneshot(public_post(
            "/api/devices/pair",
            json!({"secret": "ABCD2345", "device_name": "x", "device_kind": "mobile"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["code"], "PAIRING_NOT_FOUND");
}

#[tokio::test]
async fn a_paired_phone_can_read_but_not_change_lan_trust() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };
    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Pixel", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let phone = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();

    let (status, _) = send(get_with_token("/api/network/status", &phone)).await;
    assert_eq!(status, StatusCode::OK);
    let rename = json!({"display_name": "Phone was here"});
    let (status, body) = send(json_with_token(
        "PUT",
        "/api/network/status",
        rename.clone(),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("NETWORK_OWNER_ONLY"))
    );
    let (status, _) = send(json_with_token("PUT", "/api/network/status", rename, &desktop, "c")).await;
    assert_eq!(status, StatusCode::OK);
}

/// A request on the agent helper channel: the three runtime headers, no JWT,
/// no CSRF pair (the channel is CSRF-exempt).
fn helper_request(method: &str, uri: &str, body: serde_json::Value, helper: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in helper {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn an_agent_helper_token_cannot_manage_devices_or_lan_trust() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let conversation = "conv-agent-helper";
    common::ensure_conversation(&services, &owner, conversation).await;
    let issue = services.runtime_token_service.issue(
        owner.as_str(),
        conversation,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper = [
        ("x-aionui-runtime-token", issue.token.as_str()),
        ("x-aionui-user-id", owner.as_str()),
        ("x-aionui-conversation-id", conversation),
    ];

    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop_id = desktop["data"]["device_id"].as_str().unwrap().to_owned();
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();

    // The helper channel itself works: reads like a paired phone's succeed.
    let (status, _) = send(helper_request("GET", "/api/devices", json!(null), &helper)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(helper_request("GET", "/api/network/status", json!(null), &helper)).await;
    assert_eq!(status, StatusCode::OK);

    // Device management is refused: no pairing, no listener, no revoking others.
    let device_owner_only = (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY"));
    let (status, body) = send(helper_request("POST", "/api/devices/pairings", json!({}), &helper)).await;
    assert_eq!((status, body["code"].clone()), device_owner_only);
    let (status, body) = send(helper_request("GET", "/api/devices/listener", json!(null), &helper)).await;
    assert_eq!((status, body["code"].clone()), device_owner_only);
    let (status, body) = send(helper_request(
        "PUT",
        "/api/devices/listener",
        json!({"enabled": true}),
        &helper,
    ))
    .await;
    assert_eq!((status, body["code"].clone()), device_owner_only);
    let (status, body) = send(helper_request(
        "POST",
        &format!("/api/devices/{desktop_id}/revoke"),
        json!({}),
        &helper,
    ))
    .await;
    assert_eq!((status, body["code"].clone()), device_owner_only);

    // A pairing the desktop opened cannot be approved, read or rejected by the helper.
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Agent phone", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    for (method, uri) in [
        ("POST", format!("/api/devices/pairings/{pairing_id}/approve")),
        ("POST", format!("/api/devices/pairings/{pairing_id}/reject")),
        ("GET", format!("/api/devices/pairings/{pairing_id}")),
    ] {
        let (status, body) = send(helper_request(method, &uri, json!({}), &helper)).await;
        assert_eq!((status, body["code"].clone()), device_owner_only, "{method} {uri}");
    }
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    assert_eq!(claimed["data"]["state"], "requested", "still waiting for the owner");

    // LAN trust mutations are refused.
    let network_owner_only = (StatusCode::FORBIDDEN, json!("NETWORK_OWNER_ONLY"));
    for (method, uri, body) in [
        ("PUT", "/api/network/status", json!({"display_name": "Agent was here"})),
        (
            "POST",
            "/api/network/peers",
            json!({"url": "https://192.168.1.20:25820"}),
        ),
        (
            "POST",
            "/api/network/shares",
            json!({"peer_id": "peer-x", "label": "Agent share", "backend": "codex"}),
        ),
        ("POST", "/api/network/peers/peer-x/approve", json!({})),
        ("POST", "/api/network/peers/peer-x/revoke", json!({})),
        ("DELETE", "/api/network/peers/peer-x", json!(null)),
        ("DELETE", "/api/network/shares/share-x", json!(null)),
    ] {
        let (status, resp) = send(helper_request(method, uri, body, &helper)).await;
        assert_eq!((status, resp["code"].clone()), network_owner_only, "{method} {uri}");
    }

    // The desktop app keeps its authority, and was not revoked by the attempt.
    let (status, _) = send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(json_with_token(
        "PUT",
        "/api/network/status",
        json!({"display_name": "Owner"}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn runtime_headers_neither_forge_nor_widen_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let conversation = "conv-agent-helper";
    common::ensure_conversation(&services, &owner, conversation).await;
    let issue = services.runtime_token_service.issue(
        owner.as_str(),
        conversation,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );

    // Invalid, missing, mismatched or stale helper credentials never
    // authenticate. Failures name the case, never the credentials.
    let stale = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-ended",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    services.runtime_token_service.invalidate_conversation_id("conv-ended");
    for (case, helper) in [
        (
            "forged token",
            vec![
                ("x-aionui-runtime-token", "forged"),
                ("x-aionui-user-id", owner.as_str()),
                ("x-aionui-conversation-id", conversation),
            ],
        ),
        (
            "missing user header",
            vec![
                ("x-aionui-runtime-token", issue.token.as_str()),
                ("x-aionui-conversation-id", conversation),
            ],
        ),
        (
            "other conversation",
            vec![
                ("x-aionui-runtime-token", issue.token.as_str()),
                ("x-aionui-user-id", owner.as_str()),
                ("x-aionui-conversation-id", "conv-other"),
            ],
        ),
        (
            "invalidated token",
            vec![
                ("x-aionui-runtime-token", stale.token.as_str()),
                ("x-aionui-user-id", owner.as_str()),
                ("x-aionui-conversation-id", "conv-ended"),
            ],
        ),
    ] {
        let (status, _) = send(helper_request("POST", "/api/devices/pairings", json!({}), &helper)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
    }

    // With a JWT the JWT decides, whatever runtime headers ride along: the
    // desktop app keeps its authority, a paired phone gains none.
    let helper = [
        ("x-aionui-runtime-token", issue.token.as_str()),
        ("x-aionui-user-id", owner.as_str()),
        ("x-aionui-conversation-id", conversation),
    ];
    let with_jwt = |method: &str, uri: &str, token: &str| {
        let mut req = json_with_token(method, uri, json!({}), token, "c");
        for (name, value) in helper {
            req.headers_mut().insert(name, value.parse().unwrap());
        }
        req
    };
    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop_refresh = desktop["data"]["refresh_token"].as_str().unwrap().to_owned();
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();

    // The CSRF exemption follows the channel that authenticates: a runtime
    // header riding on a JWT or session cookie does not lift CSRF.
    let csrf_invalid = (StatusCode::FORBIDDEN, json!("CSRF_INVALID"));
    let mut bearer_with_helper = helper_request("POST", "/api/devices/pairings", json!({}), &helper);
    bearer_with_helper
        .headers_mut()
        .insert("authorization", format!("Bearer {desktop}").parse().unwrap());
    let (status, body) = send(bearer_with_helper).await;
    assert_eq!((status, body["code"].clone()), csrf_invalid, "bearer + runtime headers");
    let mut cookie_with_bogus = helper_request(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &[("x-aionui-runtime-token", "bogus")],
    );
    cookie_with_bogus
        .headers_mut()
        .insert("cookie", format!("aionui-session={desktop}").parse().unwrap());
    let (status, body) = send(cookie_with_bogus).await;
    assert_eq!(
        (status, body["code"].clone()),
        csrf_invalid,
        "cookie + bogus runtime header"
    );
    // The refresh endpoint reads the HttpOnly refresh cookie alone.
    let refresh_with = |cookie: String, csrf: Option<&str>| {
        let mut req = helper_request(
            "POST",
            "/api/auth/refresh",
            json!({}),
            &[("x-aionui-runtime-token", "bogus")],
        );
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        if let Some(csrf) = csrf {
            req.headers_mut().insert("x-csrf-token", csrf.parse().unwrap());
        }
        req
    };
    let (status, body) = send(refresh_with(format!("aionui-refresh={desktop_refresh}"), None)).await;
    assert_eq!(
        (status, body["code"].clone()),
        csrf_invalid,
        "refresh cookie + bogus runtime header"
    );
    let (status, _) = send(refresh_with(
        format!("aionui-refresh={desktop_refresh}; aionui-csrf-token=c"),
        Some("c"),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "refresh cookie with the CSRF pair");
    // The helper on its own keeps the exemption: refused by authority, not CSRF.
    let (status, body) = send(helper_request("POST", "/api/devices/pairings", json!({}), &helper)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY")),
        "helper alone"
    );

    let (status, pairing) = send(with_jwt("POST", "/api/devices/pairings", &desktop)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Pixel", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let phone = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();
    let (status, body) = send(with_jwt("POST", "/api/devices/pairings", &phone)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY"))
    );
}

#[tokio::test]
async fn only_the_desktop_app_uses_filesystem_routes_beyond_upload() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };
    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Pixel", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let phone = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    common::ensure_conversation(&services, &owner, "conv-agent-helper").await;
    let issue = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-agent-helper",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper = [
        ("x-aionui-runtime-token", issue.token.as_str()),
        ("x-aionui-user-id", owner.as_str()),
        ("x-aionui-conversation-id", "conv-agent-helper"),
    ];

    // A harmless listing of this test's own folder.
    let folder = dir.path().to_string_lossy().into_owned();
    let listing = json!({"dir": folder, "root": folder});
    let fs_owner_only = (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"));

    let (status, body) = send(json_with_token("POST", "/api/fs/dir", listing.clone(), &phone, "c")).await;
    assert_eq!((status, body["code"].clone()), fs_owner_only, "paired phone");
    let (status, body) = send(helper_request("POST", "/api/fs/dir", listing.clone(), &helper)).await;
    assert_eq!((status, body["code"].clone()), fs_owner_only, "agent helper");
    let (status, _) = send(json_with_token("POST", "/api/fs/dir", listing, &desktop, "c")).await;
    assert_eq!(status, StatusCode::OK, "desktop app");

    // The same host file effects through other route groups (audit run-2
    // SEC-C). Paths are missing or scratch-only, so a reached handler does
    // nothing on this machine.
    let missing = dir.path().join("missing.txt").to_string_lossy().into_owned();
    let effects = [
        ("/api/shell/open-file", json!({"file_path": missing})),
        ("/api/shell/show-item-in-folder", json!({"file_path": missing})),
        (
            "/api/shell/open-folder-with",
            json!({"folder_path": missing, "tool": "finder"}),
        ),
        (
            "/api/skills/export-symlink",
            json!({"skill_path": missing, "target_dir": dir.path().join("t").to_string_lossy()}),
        ),
        (
            "/api/projects/no-such-project/folders",
            json!({"uri": format!("file://{folder}")}),
        ),
        (
            "/api/document/convert",
            json!({"file_path": missing, "to": "markdown", "workspace": folder}),
        ),
        ("/api/excel-preview/start", json!({"file_path": missing})),
        (
            "/api/assistants",
            json!({"name": "test", "agent_id": "632f31d2", "avatar": missing}),
        ),
        (
            "/api/assistants/import",
            json!({"assistants": [{"name": "test", "agent_id": "632f31d2", "avatar": missing}]}),
        ),
    ];
    for (uri, body) in effects {
        let (status, code) = send(json_with_token("POST", uri, body.clone(), &phone, "c")).await;
        assert_eq!((status, code["code"].clone()), fs_owner_only, "paired phone: {uri}");
        let (status, code) = send(helper_request("POST", uri, body, &helper)).await;
        assert_eq!((status, code["code"].clone()), fs_owner_only, "agent helper: {uri}");
    }

    // Listing a conversation's chosen workspace is a host read too.
    let browse = Request::builder()
        .method("GET")
        .uri("/api/conversations/no-such-conversation/workspace")
        .header("authorization", format!("Bearer {phone}"))
        .body(Body::empty())
        .unwrap();
    let (status, code) = send(browse).await;
    assert_eq!(
        (status, code["code"].clone()),
        fs_owner_only,
        "paired phone: workspace listing"
    );

    // Host-path skill routes stay open to the agent helper CLI, which uses
    // them, but not to paired devices.
    let skills = [
        ("/api/skills/info", json!({"skill_path": missing})),
        ("/api/skills/scan", json!({"folder_path": folder})),
        ("/api/skills/import", json!({"skill_path": missing})),
        ("/api/skills/external-paths", json!({"name": "x", "path": folder})),
    ];
    for (uri, body) in skills {
        let (status, code) = send(json_with_token("POST", uri, body.clone(), &phone, "c")).await;
        assert_eq!((status, code["code"].clone()), fs_owner_only, "paired phone: {uri}");
        let (status, _) = send(helper_request("POST", uri, body, &helper)).await;
        assert_ne!(status, StatusCode::FORBIDDEN, "agent helper: {uri}");
    }

    let (status, _) = send(json_with_token(
        "POST",
        "/api/shell/open-file",
        json!({"file_path": missing}),
        &desktop,
        "c",
    ))
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN, "desktop app reaches the shell handler");

    // Attachments keep working for a paired phone.
    let boundary = "aionx-boundary";
    let upload = Request::builder()
        .method("POST")
        .uri("/api/fs/upload")
        .header("authorization", format!("Bearer {phone}"))
        .header("x-csrf-token", "c")
        .header("cookie", "aionui-csrf-token=c")
        .header("content-type", format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n"
        )))
        .unwrap();
    let (status, _) = send(upload).await;
    assert_eq!(status, StatusCode::OK, "phone attachment upload");
}

/// ADR-019: a scheduled job runs its agent in full-auto mode, unattended, so
/// arming one is a host effect. Paired phones and browsers may list, inspect
/// and pause jobs; everything else is for the desktop app (and the helper).
#[tokio::test]
async fn a_paired_device_may_inspect_and_pause_cron_jobs_only() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };
    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Phone", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let device = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    common::ensure_conversation(&services, &owner, "conv-agent-helper").await;
    let issue = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-agent-helper",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper = [
        ("x-aionui-runtime-token", issue.token.as_str()),
        ("x-aionui-user-id", owner.as_str()),
        ("x-aionui-conversation-id", "conv-agent-helper"),
    ];

    let (status, _) = send(json_with_token(
        "POST",
        "/api/assistants",
        json!({"id": "cron-device-assistant", "name": "Cron Assistant", "agent_id": "2d23ff1c"}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let job_body = json!({
        "name": "Hourly note",
        "schedule": {"kind": "every", "every_ms": 3_600_000, "description": "hourly"},
        "message": "Reply with OK.",
        "conversation_id": "",
        "created_by": "user",
        "execution_mode": "new_conversation",
        "agent_config": {"name": "Cron Assistant", "assistant_id": "cron-device-assistant"}
    });
    let desktop_only = (StatusCode::FORBIDDEN, json!("CRON_DESKTOP_ONLY"));

    // Arming a job: refused for the device, allowed for the desktop app.
    let (status, body) = send(json_with_token(
        "POST",
        "/api/cron/jobs",
        job_body.clone(),
        &device,
        "c",
    ))
    .await;
    assert_eq!((status, body["code"].clone()), desktop_only, "device create");
    let (status, created) = send(json_with_token(
        "POST",
        "/api/cron/jobs",
        job_body.clone(),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "desktop create: {created}");
    let id = created["data"]["id"].as_str().unwrap().to_owned();
    let job = format!("/api/cron/jobs/{id}");

    // Reading and pausing work for the device.
    for uri in ["/api/cron/jobs".to_owned(), job.clone(), format!("{job}/conversations")] {
        let (status, _) = send(get_with_token(&uri, &device)).await;
        assert_eq!(status, StatusCode::OK, "device read {uri}");
    }
    let (status, paused) = send(json_with_token("PUT", &job, json!({"enabled": false}), &device, "c")).await;
    assert_eq!(status, StatusCode::OK, "device pause");
    assert_eq!(paused["data"]["enabled"], false);

    // Everything else is refused for the device.
    let refused = [
        ("PUT", job.clone(), json!({"enabled": true})),
        ("PUT", job.clone(), json!({"enabled": false, "message": "Do more."})),
        ("PUT", job.clone(), json!({"name": "Renamed"})),
        ("POST", format!("{job}/run"), json!({})),
        ("POST", format!("{job}/skill"), json!({"content": "Do something"})),
        (
            "POST",
            "/api/internal/conversation-cron/create".to_owned(),
            json!({"name": "x", "schedule": "0 9 * * *", "message": "x"}),
        ),
        ("POST", "/api/cron/internal/system-resume".to_owned(), json!({})),
    ];
    for (method, uri, body) in refused {
        let (status, code) = send(json_with_token(method, &uri, body, &device, "c")).await;
        assert_eq!((status, code["code"].clone()), desktop_only, "device {method} {uri}");
    }
    let (status, code) = send(delete_with_token(&format!("{job}/skill"), &device, "c")).await;
    assert_eq!((status, code["code"].clone()), desktop_only, "device delete skill");
    let (status, code) = send(delete_with_token(&job, &device, "c")).await;
    assert_eq!((status, code["code"].clone()), desktop_only, "device delete");

    // The helper keeps its owner-equivalent access; the desktop resumes and deletes.
    let (status, _) = send(helper_request("GET", "/api/cron/jobs", json!(null), &helper)).await;
    assert_eq!(status, StatusCode::OK, "helper list");
    let (status, resumed) = send(json_with_token("PUT", &job, json!({"enabled": true}), &desktop, "c")).await;
    assert_eq!(status, StatusCode::OK, "desktop resume");
    assert_eq!(resumed["data"]["enabled"], true);
    let (status, _) = send(delete_with_token(&job, &desktop, "c")).await;
    assert_eq!(status, StatusCode::OK, "desktop delete");
}

/// Policy B (Jev 057): logs in by password or QR and returns
/// (access token, refresh cookie value, csrf).
async fn browser_login(app: &axum::Router, uri: &str, body: serde_json::Value, ua: Option<&str>) -> (String, String) {
    let mut req = public_post(uri, body);
    if let Some(ua) = ua {
        req.headers_mut().insert("user-agent", ua.parse().unwrap());
    }
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{uri} login");
    let refresh = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("aionui-refresh="))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .expect("refresh cookie");
    let token = body_json(resp).await["token"].as_str().unwrap().to_owned();
    (token, refresh)
}

async fn refresh_status(app: &axum::Router, refresh: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/refresh")
        .header("content-type", "application/json")
        .header("cookie", format!("aionui-refresh={refresh}; aionui-csrf-token=c"))
        .header("x-csrf-token", "c")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn assert_listed_restricted_and_revocable(
    app: &axum::Router,
    desktop: &str,
    token: &str,
    refresh: &str,
    expected_name: &str,
) {
    let send = |req: Request<Body>| async move {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    };
    // The login session sees itself as the current browser device.
    let (status, own) = send(get_with_token("/api/devices", token)).await;
    assert_eq!(status, StatusCode::OK, "list as browser: {own}");
    let me = own["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["current"] == true)
        .cloned()
        .unwrap_or_else(|| panic!("login session is device-bound: {own}"));
    assert_eq!(me["kind"], "browser");
    assert_eq!(me["name"], expected_name);
    let device_id = me["id"].as_str().unwrap().to_owned();
    // The desktop's paired-device list shows it.
    let (_, listed) = send(get_with_token("/api/devices", desktop)).await;
    assert!(
        listed["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == device_id.as_str()),
        "desktop list: {listed}"
    );
    // Restricted like a paired browser: no host files, no device/LAN management.
    let (status, body) = send(json_with_token(
        "POST",
        "/api/fs/image-base64",
        json!({"path": "/etc/hosts"}),
        token,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"))
    );
    let (status, body) = send(json_with_token("POST", "/api/devices/pairings", json!({}), token, "c")).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY"))
    );
    let (status, body) = send(json_with_token(
        "PUT",
        "/api/network/status",
        json!({"display_name": "x"}),
        token,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("NETWORK_OWNER_ONLY"))
    );
    // The desktop revokes it alone; both its tokens die.
    let (status, _) = send(json_with_token(
        "POST",
        &format!("/api/devices/{device_id}/revoke"),
        json!({}),
        desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(get_with_token("/api/auth/user", token)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("DEVICE_REVOKED"))
    );
    let (status, body) = refresh_status(app, refresh).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("DEVICE_REVOKED")),
        "refresh: {body}"
    );
    let (status, _) = send(get_with_token("/api/auth/user", desktop)).await;
    assert_eq!(status, StatusCode::OK, "desktop unaffected");
}

#[tokio::test]
async fn password_login_creates_a_listed_revocable_browser_device() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = common::build_app_with_mock_agents_at(tmp.path()).await;
    let desktop = common::desktop_session(&app, tmp.path()).await;
    let _ = common::setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let login = json!({"username": "admin", "password": "Passw0rd!Long"});
    let ua = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
    let (token, refresh) = browser_login(&app, "/login", login.clone(), Some(ua)).await;
    assert_listed_restricted_and_revocable(&app, &desktop, &token, &refresh, "Chrome (password)").await;
    let (token, refresh) = browser_login(&app, "/login", login, None).await;
    assert_listed_restricted_and_revocable(&app, &desktop, &token, &refresh, "Browser (password)").await;
}

#[tokio::test]
async fn qr_login_creates_a_listed_revocable_browser_device() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = common::build_app_with_mock_agents_at(tmp.path()).await;
    let desktop = common::desktop_session(&app, tmp.path()).await;
    let _ = common::setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let qr = services.qr_token_store.generate();
    let (token, refresh) = browser_login(&app, "/api/auth/qr-login", json!({"qr_token": qr}), None).await;
    assert_listed_restricted_and_revocable(&app, &desktop, &token, &refresh, "Browser (QR)").await;
}

#[tokio::test]
async fn old_deviceless_tokens_keep_working_until_they_expire() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, services) = common::build_app_with_mock_agents_at(tmp.path()).await;
    let _ = common::setup_and_login(&mut app, &services, "admin", "Passw0rd!Long").await;
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap();
    let (access, refresh) = services
        .jwt_service
        .sign_session_pair(&owner.id, "admin", owner.session_generation, None)
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/auth/user", &access))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "device-less access token");
    let (status, body) = refresh_status(&app, &refresh).await;
    assert_eq!(status, StatusCode::OK, "device-less refresh: {body}");
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/devices/pairings",
            json!({}),
            &access,
            "c",
        ))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["code"], "DEVICE_OWNER_ONLY", "still restricted");
}

/// Policy B (Jev 057) for the AionPro external-account path: the session exchange
/// binds a restricted `browser` device named "External account".
#[tokio::test]
async fn external_session_creates_a_listed_revocable_browser_device() {
    let tmp = tempfile::tempdir().unwrap();
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        identity_mode: aionui_app::IdentityMode::AionPro,
        bootstrap_secret: Some("bootstrap-secret".into()),
        data_dir: tmp.path().to_path_buf(),
        work_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();
    let app = aionui_app::create_router(&services).await.unwrap();
    let internal = |method: &str, uri: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-aioncore-bootstrap-secret", "bootstrap-secret")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let resp = app
        .clone()
        .oneshot(internal(
            "PUT",
            "/api/auth/internal/external-users/ext-1",
            json!({"user_type": "aionpro", "username": "Ext"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(internal(
            "POST",
            "/api/auth/internal/external-sessions",
            json!({"user_type": "aionpro", "external_user_id": "ext-1"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = |name: &str| {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                c.strip_prefix(&format!("{name}="))
                    .map(|c| c.split(';').next().unwrap().to_owned())
            })
            .expect("cookie")
    };
    let refresh = cookie("aionui-refresh");
    let token = cookie("aionui-session");
    let send = |req: Request<Body>| async {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    };
    // /api/devices is host-owner only (single-owner model), so read the row directly.
    let user_id = body_json(resp).await["data"]["user"]["id"].as_str().unwrap().to_owned();
    let repo = aionui_db::SqliteDeviceRepository::new(services.database.pool().clone());
    let rows = aionui_db::IDeviceRepository::list(&repo, &user_id).await.unwrap();
    assert_eq!(rows.len(), 1, "external session is device-bound");
    assert_eq!(
        (rows[0].kind.as_str(), rows[0].name.as_str()),
        ("browser", "External account")
    );
    let device_id = rows[0].id.clone();
    for (method, uri, body, code) in [
        (
            "POST",
            "/api/fs/image-base64",
            json!({"path": "/etc/hosts"}),
            "FS_OWNER_ONLY",
        ),
        ("POST", "/api/devices/pairings", json!({}), "DEVICE_OWNER_ONLY"),
        (
            "PUT",
            "/api/network/status",
            json!({"display_name": "x"}),
            "NETWORK_OWNER_ONLY",
        ),
    ] {
        let (status, body) = send(json_with_token(method, uri, body, &token, "c")).await;
        assert_eq!(
            (status, body["code"].clone()),
            (StatusCode::FORBIDDEN, json!(code)),
            "{uri}"
        );
    }
    let (status, _) = send(get_with_token("/api/auth/user", &token)).await;
    assert_eq!(status, StatusCode::OK, "live before revoke");
    // Revoking that one device kills both of its tokens.
    assert!(
        aionui_db::IDeviceRepository::revoke(&repo, &user_id, &device_id, aionui_common::now_ms())
            .await
            .unwrap()
    );
    let (status, body) = send(get_with_token("/api/auth/user", &token)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("DEVICE_REVOKED"))
    );
    let (status, body) = refresh_status(&app, &refresh).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("DEVICE_REVOKED"))
    );
}
