//! ADR-013 for chat channels. Connecting a bot and approving a chat user grant access to the
//! owner's agents, like approving a device, so a paired phone or browser (and the agent
//! helper) gets 403 `FS_OWNER_ONLY`. Disabling, rejecting and revoking only take access away
//! and stay open to the phone. Choosing the platform's assistant or model and syncing its
//! settings are desktop-only too.

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, desktop_and_phone, json_with_token};

#[tokio::test]
async fn a_phone_cannot_connect_a_bot_or_approve_a_chat_user_but_can_take_access_away() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _services, _) = build_app_with_skill_paths(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let send = |method: &str, uri: &str, body: Value, token: &str| {
        let req = json_with_token(method, uri, body, token, "c");
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            (status, common::body_json(resp).await)
        }
    };
    let refused = json!("FS_OWNER_ONLY");

    let grants = [
        (
            "/api/channel/plugins/enable",
            json!({"plugin_id": "telegram", "config": {"token": "123:phone"}}),
        ),
        (
            "/api/channel/plugins/test",
            json!({"plugin_id": "telegram", "token": "123:phone"}),
        ),
        ("/api/channel/pairings/approve", json!({"code": "ABC123"})),
    ];
    for (uri, body) in &grants {
        let (status, resp) = send("POST", uri, body.clone(), &phone).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {uri}: {resp}"
        );
    }
    // The desktop passes the gate (an unknown code is the service's answer, not the gate's).
    // Enable and test are not called from the desktop: they would reach the real bot API.
    let (status, resp) = send(
        "POST",
        "/api/channel/pairings/approve",
        json!({"code": "ABC123"}),
        &desktop,
    )
    .await;
    assert_ne!(resp["code"], refused, "desktop approve: {status} {resp}");

    let removals = [
        ("/api/channel/plugins/disable", json!({"plugin_id": "telegram"})),
        ("/api/channel/pairings/reject", json!({"code": "ABC123"})),
        (
            "/api/channel/users/revoke",
            json!({"user_id": "nobody", "platform_user_id": "nobody", "platform": "telegram"}),
        ),
    ];
    for (uri, body) in &removals {
        let (status, resp) = send("POST", uri, body.clone(), &phone).await;
        assert_ne!(resp["code"], refused, "phone {uri}: {status} {resp}");
        assert_ne!(status, StatusCode::FORBIDDEN, "phone {uri}: {resp}");
    }
}

/// Choosing which assistant and model answer a chat platform, and syncing its settings (which
/// clears its sessions), are owner decisions too: a phone and the agent helper are refused,
/// and the settings do not change.
#[tokio::test]
async fn only_the_desktop_changes_which_assistant_answers_a_chat_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, _) = build_app_with_skill_paths(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-channel",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            (status, common::body_json(resp).await)
        }
    };
    let as_helper = |method: &str, uri: &str, body: &Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-aionui-runtime-token", helper.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-channel")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let refused = json!("FS_OWNER_ONLY");
    let settings = "/api/channel/settings/telegram";
    let (_, before) = send(json_with_token("GET", settings, json!({}), &desktop, "c")).await;

    let changes = [
        (
            "PUT",
            "/api/channel/settings/telegram/assistant",
            json!({"assistant_id": "phone-choice"}),
        ),
        (
            "PUT",
            "/api/channel/settings/telegram/default-model",
            json!({"id": "provider-x", "use_model": "model-x"}),
        ),
        ("POST", "/api/channel/settings/sync", json!({"platform": "telegram"})),
    ];
    for (method, uri, body) in &changes {
        let (status, resp) = send(json_with_token(method, uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {uri}: {resp}"
        );
        let (status, resp) = send(as_helper(method, uri, body)).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "helper {uri}: {resp}"
        );
    }
    let (_, after) = send(json_with_token("GET", settings, json!({}), &desktop, "c")).await;
    assert_eq!(before, after, "refused changes left the settings as they were");
    let (status, _) = send(json_with_token("GET", settings, json!({}), &phone, "c")).await;
    assert_eq!(status, StatusCode::OK, "the phone still reads the settings");

    // The desktop passes the gate on every change.
    for (method, uri, body) in &changes {
        let (status, resp) = send(json_with_token(method, uri, body.clone(), &desktop, "c")).await;
        assert_ne!(resp["code"], refused, "desktop {uri}: {status} {resp}");
        assert_ne!(status, StatusCode::FORBIDDEN, "desktop {uri}: {resp}");
    }
}
