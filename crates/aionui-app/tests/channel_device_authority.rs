//! ADR-013 for chat channels. Connecting a bot and approving a chat user grant access to the
//! owner's agents, like approving a device, so a paired phone or browser (and the agent
//! helper) gets 403 `FS_OWNER_ONLY`. Disabling, rejecting and revoking only take access away
//! and stay open to the phone.

mod common;

use axum::http::StatusCode;
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
