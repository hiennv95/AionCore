//! Security tests for assistant avatar handling under ADR-013.
//!
//! Asserts that host filesystem effects (local file copying via avatar paths)
//! are restricted to desktop sessions only, while paired devices (phones, web
//! browsers) and agent runtime helpers cannot copy host files via assistant
//! creation, update, or bulk import. Non-host avatar values (Unicode emojis,
//! builtin/managed avatar route references, null) remain open to all
//! authenticated callers.
//!
//! Historical Red Behavior (before ADR-013 guard):
//! Untrusted callers (paired devices, runtime helpers) submitting host file
//! paths (absolute, file://, relative, symlink) received HTTP 201 CREATED,
//! which copied arbitrary local host files into the managed user avatar store.
//!
//! Enforced Behavior (ADR-013):
//! A pure lexical classifier runs in the route layer before any filesystem
//! inspection or DB mutation. Any non-safe avatar input from an untrusted caller
//! is rejected immediately with HTTP 403 FS_OWNER_ONLY without route-layer
//! filesystem probes, preventing host file disclosure and unauthorized writes.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use common::{body_json, build_app_with_skill_paths, json_with_token};

fn public_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn json_with_cookie(method_str: &str, uri: &str, body: serde_json::Value, cookie: &str, csrf: &str) -> Request<Body> {
    Request::builder()
        .method(method_str)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-csrf-token", csrf)
        .header("cookie", format!("{cookie}; aionui-csrf-token={csrf}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn helper_request(method_str: &str, uri: &str, body: serde_json::Value, helper: &[(&str, &str); 3]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method_str)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in helper {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

#[tokio::test]
async fn assistant_avatar_host_file_copy_is_desktop_only() {
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

    let user_avatars_dir = dir
        .path()
        .join("assistant-avatars")
        .join("users")
        .join("system_default_user");

    // 1. Establish Desktop App session
    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();

    // 2. Establish Paired Phone session
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired_phone) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Pixel", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id_phone = paired_phone["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id_phone}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed_phone) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id_phone, "claim_token": paired_phone["data"]["claim_token"]}),
    ))
    .await;
    let phone = claimed_phone["data"]["session"]["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // 3. Establish Paired Browser session
    let (_, pairing_browser) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired_browser) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing_browser["data"]["secret"], "device_name": "Chrome Web", "device_kind": "browser"}),
    ))
    .await;
    let pairing_id_browser = paired_browser["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id_browser}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let claim_resp = app
        .clone()
        .oneshot(public_post(
            "/api/devices/pair/claim",
            json!({"pairing_id": pairing_id_browser, "claim_token": paired_browser["data"]["claim_token"]}),
        ))
        .await
        .unwrap();
    let browser_cookie = claim_resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| v.to_str().ok().filter(|s| s.starts_with("aionui-session=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    // 4. Establish Runtime Helper token
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
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

    // Create harmless temporary marker image files for candidate path table
    let marker_bytes = b"\x89PNG\r\n\x1a\nfake-png-bytes";
    let marker_path = dir.path().join("harmless_marker.png");
    std::fs::write(&marker_path, marker_bytes).unwrap();
    let abs_path_str = marker_path.to_string_lossy().to_string();
    let file_uri_str = format!("file://{abs_path_str}");
    let rel_path_str = "harmless_marker.png".to_string();

    let symlink_path = dir.path().join("harmless_symlink.png");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&marker_path, &symlink_path).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(&marker_path, &symlink_path).unwrap();
    let symlink_path_str = symlink_path.to_string_lossy().to_string();

    let candidate_paths = [
        ("absolute", abs_path_str.as_str()),
        ("file_uri", file_uri_str.as_str()),
        ("relative", rel_path_str.as_str()),
        ("symlink", symlink_path_str.as_str()),
    ];

    let fs_owner_only = (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"));

    // =========================================================================
    // 1. POSITIVE CONTROL: Desktop App can use local file avatar (creates managed copy)
    // =========================================================================
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants",
        json!({
            "id": "desktop-baseline-assistant",
            "name": "Desktop Baseline Assistant",
            "agent_id": "632f31d2",
            "avatar": abs_path_str,
        }),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "desktop app must be permitted to create assistant with local avatar file"
    );
    assert!(
        body["data"]["avatar"]
            .as_str()
            .unwrap()
            .contains("/api/assistants/desktop-baseline-assistant/avatar")
    );
    let desktop_avatar_file = user_avatars_dir.join("desktop-baseline-assistant.png");
    assert!(
        desktop_avatar_file.exists(),
        "desktop avatar file must be materialized in user avatars dir"
    );
    assert_eq!(
        std::fs::read(&desktop_avatar_file).unwrap(),
        marker_bytes,
        "desktop avatar file content must match source marker"
    );

    // =========================================================================
    // 2. DENIAL ASSERTIONS (CREATE): Table coverage for all candidate paths & callers
    // =========================================================================
    for (candidate_kind, candidate_val) in candidate_paths {
        // Phone create denial
        let assistant_id = format!("phone-create-{candidate_kind}");
        let (status, body) = send(json_with_token(
            "POST",
            "/api/assistants",
            json!({
                "id": &assistant_id,
                "name": "Phone Denied",
                "agent_id": "632f31d2",
                "avatar": candidate_val,
            }),
            &phone,
            "c",
        ))
        .await;
        assert_eq!(
            (status, body["code"].clone()),
            fs_owner_only,
            "phone create with {candidate_kind} path must fail 403 FS_OWNER_ONLY"
        );
        assert!(
            !user_avatars_dir.join(format!("{assistant_id}.png")).exists(),
            "destination file must NOT be created on rejected phone create ({candidate_kind})"
        );

        // Browser create denial
        let assistant_id = format!("browser-create-{candidate_kind}");
        let (status, body) = send(json_with_cookie(
            "POST",
            "/api/assistants",
            json!({
                "id": &assistant_id,
                "name": "Browser Denied",
                "agent_id": "632f31d2",
                "avatar": candidate_val,
            }),
            &browser_cookie,
            "c",
        ))
        .await;
        assert_eq!(
            (status, body["code"].clone()),
            fs_owner_only,
            "browser create with {candidate_kind} path must fail 403 FS_OWNER_ONLY"
        );
        assert!(
            !user_avatars_dir.join(format!("{assistant_id}.png")).exists(),
            "destination file must NOT be created on rejected browser create ({candidate_kind})"
        );

        // Runtime Helper create denial
        let assistant_id = format!("helper-create-{candidate_kind}");
        let (status, body) = send(helper_request(
            "POST",
            "/api/assistants",
            json!({
                "id": &assistant_id,
                "name": "Helper Denied",
                "agent_id": "632f31d2",
                "avatar": candidate_val,
            }),
            &helper,
        ))
        .await;
        assert_eq!(
            (status, body["code"].clone()),
            fs_owner_only,
            "runtime helper create with {candidate_kind} path must fail 403 FS_OWNER_ONLY"
        );
        assert!(
            !user_avatars_dir.join(format!("{assistant_id}.png")).exists(),
            "destination file must NOT be created on rejected helper create ({candidate_kind})"
        );
    }

    // =========================================================================
    // 3. DENIAL ASSERTIONS (UPDATE): Phone, Browser, and Helper update controls
    // =========================================================================
    // First verify existing desktop avatar bytes before update attacks
    let original_bytes = std::fs::read(&desktop_avatar_file).unwrap();

    // Phone update denial
    let (status, body) = send(json_with_token(
        "PUT",
        "/api/assistants/desktop-baseline-assistant",
        json!({"avatar": abs_path_str}),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "phone update with host path must fail 403 FS_OWNER_ONLY"
    );

    // Browser update denial
    let (status, body) = send(json_with_cookie(
        "PUT",
        "/api/assistants/desktop-baseline-assistant",
        json!({"avatar": file_uri_str}),
        &browser_cookie,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "browser update with host path must fail 403 FS_OWNER_ONLY"
    );

    // Helper update denial
    let (status, body) = send(helper_request(
        "PUT",
        "/api/assistants/desktop-baseline-assistant",
        json!({"avatar": rel_path_str}),
        &helper,
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "helper update with host path must fail 403 FS_OWNER_ONLY"
    );

    // Symlink update denial via phone
    let (status, body) = send(json_with_token(
        "PUT",
        "/api/assistants/desktop-baseline-assistant",
        json!({"avatar": symlink_path_str}),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "phone update with symlink path must fail 403 FS_OWNER_ONLY"
    );

    // Assert existing avatar bytes and destination file are COMPLETELY UNCHANGED
    assert_eq!(
        std::fs::read(&desktop_avatar_file).unwrap(),
        original_bytes,
        "existing avatar file bytes must remain untouched after rejected update attempts"
    );

    // Assert assistant definition in DB remains intact
    let (status, body) = send(json_with_token(
        "GET",
        "/api/assistants/desktop-baseline-assistant",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["profile"]["avatar"]
            .as_str()
            .unwrap()
            .contains("/api/assistants/desktop-baseline-assistant/avatar"),
        "assistant avatar route in DB must remain unchanged"
    );

    // =========================================================================
    // 4. DENIAL ASSERTIONS (IMPORT): Phone, Browser, Helper & Atomic Rejection
    // =========================================================================
    // Phone import denial
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants/import",
        json!({
            "assistants": [{
                "id": "phone-import-host",
                "name": "Phone Import",
                "agent_id": "632f31d2",
                "avatar": abs_path_str,
            }]
        }),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "phone import with host path must fail 403 FS_OWNER_ONLY"
    );
    assert!(!user_avatars_dir.join("phone-import-host.png").exists());

    // Browser import denial
    let (status, body) = send(json_with_cookie(
        "POST",
        "/api/assistants/import",
        json!({
            "assistants": [{
                "id": "browser-import-host",
                "name": "Browser Import",
                "agent_id": "632f31d2",
                "avatar": file_uri_str,
            }]
        }),
        &browser_cookie,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "browser import with host path must fail 403 FS_OWNER_ONLY"
    );
    assert!(!user_avatars_dir.join("browser-import-host.png").exists());

    // Helper import denial
    let (status, body) = send(helper_request(
        "POST",
        "/api/assistants/import",
        json!({
            "assistants": [{
                "id": "helper-import-host",
                "name": "Helper Import",
                "agent_id": "632f31d2",
                "avatar": rel_path_str,
            }]
        }),
        &helper,
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "helper import with host path must fail 403 FS_OWNER_ONLY"
    );
    assert!(!user_avatars_dir.join("helper-import-host.png").exists());

    // Mixed batch atomic denial: one legit emoji + one malicious host path
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants/import",
        json!({
            "assistants": [
                {
                    "id": "import-atomic-legit",
                    "name": "Atomic Legit",
                    "agent_id": "632f31d2",
                    "avatar": "⚡",
                },
                {
                    "id": "import-atomic-malicious",
                    "name": "Atomic Malicious",
                    "agent_id": "632f31d2",
                    "avatar": symlink_path_str,
                }
            ]
        }),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        fs_owner_only,
        "mixed import with host path must fail 403 FS_OWNER_ONLY"
    );
    assert!(!user_avatars_dir.join("import-atomic-legit.png").exists());
    assert!(!user_avatars_dir.join("import-atomic-malicious.png").exists());

    // Verify atomicity in DB: neither assistant was inserted
    let (status, body) = send(json_with_token("GET", "/api/assistants", json!({}), &phone, "c")).await;
    assert_eq!(status, StatusCode::OK);
    let assistants = body["data"].as_array().unwrap();
    assert!(
        !assistants.iter().any(|a| a["id"] == "import-atomic-legit"),
        "atomic reject: legit assistant was not inserted"
    );
    assert!(
        !assistants.iter().any(|a| a["id"] == "import-atomic-malicious"),
        "atomic reject: malicious assistant was not inserted"
    );

    // =========================================================================
    // 5. SAFE MIXED IMPORT SUCCESS: All-safe entries (emoji, builtin route, null)
    // =========================================================================
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants/import",
        json!({
            "assistants": [
                {
                    "id": "mixed-safe-emoji",
                    "name": "Mixed Safe Emoji",
                    "agent_id": "632f31d2",
                    "avatar": "🚀",
                },
                {
                    "id": "mixed-safe-builtin-ref",
                    "name": "Mixed Safe Builtin Ref",
                    "agent_id": "632f31d2",
                    "avatar": "/api/assistants/desktop-baseline-assistant/avatar",
                },
                {
                    "id": "mixed-safe-null",
                    "name": "Mixed Safe Null",
                    "agent_id": "632f31d2",
                    "avatar": null,
                }
            ]
        }),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "safe mixed bulk import from paired phone must succeed"
    );
    assert_eq!(body["data"]["imported"], 3);
    assert_eq!(body["data"]["failed"], 0);

    // Assert filesystem effects of safe mixed import:
    // - Builtin route reference correctly copied the managed avatar asset on disk
    let mixed_copied_avatar = user_avatars_dir.join("mixed-safe-builtin-ref.png");
    assert!(
        mixed_copied_avatar.exists(),
        "mixed-safe-builtin-ref avatar must exist in user avatars dir"
    );
    assert_eq!(
        std::fs::read(&mixed_copied_avatar).unwrap(),
        marker_bytes,
        "mixed-safe-builtin-ref avatar bytes must match referenced assistant avatar"
    );
    // - Emoji and null avatars must NOT produce any files on disk
    assert!(
        !user_avatars_dir.join("mixed-safe-emoji.png").exists(),
        "emoji avatar must not create avatar file"
    );
    assert!(
        !user_avatars_dir.join("mixed-safe-null.png").exists(),
        "null avatar must not create avatar file"
    );

    // =========================================================================
    // 6. POSITIVE CONTROLS: Individual safe operations for Phone & Browser
    // =========================================================================
    // Phone create with Emoji
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants",
        json!({
            "id": "phone-individual-emoji",
            "name": "Phone Emoji",
            "agent_id": "632f31d2",
            "avatar": "🎨",
        }),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["data"]["avatar"], "🎨");

    // Browser create with Builtin Ref
    let (status, body) = send(json_with_cookie(
        "POST",
        "/api/assistants",
        json!({
            "id": "browser-individual-builtin-ref",
            "name": "Browser Builtin Ref",
            "agent_id": "632f31d2",
            "avatar": "/api/assistants/desktop-baseline-assistant/avatar",
        }),
        &browser_cookie,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        body["data"]["avatar"]
            .as_str()
            .unwrap()
            .contains("/api/assistants/browser-individual-builtin-ref/avatar")
    );

    // Phone create with Null
    let (status, body) = send(json_with_token(
        "POST",
        "/api/assistants",
        json!({
            "id": "phone-individual-null",
            "name": "Phone Null",
            "agent_id": "632f31d2",
            "avatar": null,
        }),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["data"]["avatar"].is_null());

    // Phone update with Emoji
    let (status, body) = send(json_with_token(
        "PUT",
        "/api/assistants/phone-individual-emoji",
        json!({"avatar": "🎯"}),
        &phone,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["avatar"], "🎯");

    // Browser update to clear avatar with empty string
    let (status, body) = send(json_with_cookie(
        "PUT",
        "/api/assistants/browser-individual-builtin-ref",
        json!({"avatar": ""}),
        &browser_cookie,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["avatar"].is_null());
}
