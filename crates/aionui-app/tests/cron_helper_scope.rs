//! C4 (Jev 056, owner decision 2026-10-29): an agent's helper CLI may only
//! manage cron jobs bound to its own conversation, in that conversation's own
//! approval mode, with no full-auto escalation. The owner desktop keeps full
//! access.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use common::{body_json, build_app, json_with_token};

const ASSISTANT_ID: &str = "cron-helper-assistant";
const OWN: &str = "conv-helper-own";
const OTHER: &str = "conv-helper-other";

struct Fixture {
    app: axum::Router,
    token: String,
    csrf: String,
    owner: String,
    helper_token: String,
}

async fn fixture() -> (Fixture, aionui_app::AppServices) {
    let (app, services) = build_app().await;
    let (token, csrf) = common::desktop_login(&app, &services).await;
    let owner = services
        .user_repo
        .find_by_username("admin")
        .await
        .unwrap()
        .expect("admin user")
        .id;
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/assistants",
            json!({ "id": ASSISTANT_ID, "name": "Cron Helper Assistant", "agent_id": "2d23ff1c" }),
            &token,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    common::ensure_conversation(&services, &owner, OWN).await;
    common::ensure_conversation(&services, &owner, OTHER).await;
    let helper_token = services
        .runtime_token_service
        .issue(
            &owner,
            OWN,
            TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
            [RuntimeTokenScope::ConversationHelper],
        )
        .token
        .as_str()
        .to_owned();
    (
        Fixture {
            app,
            token,
            csrf,
            owner,
            helper_token,
        },
        services,
    )
}

fn job_body(conversation_id: &str) -> Value {
    json!({
        "name": "Helper job",
        "schedule": { "kind": "every", "every_ms": 60000 },
        "message": "hello",
        "conversation_id": conversation_id,
        "created_by": "agent"
    })
}

impl Fixture {
    async fn helper(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-aionui-runtime-token", self.helper_token.as_str())
            .header("x-aionui-user-id", self.owner.as_str())
            .header("x-aionui-conversation-id", OWN);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let req = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn owner(&self, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .app
            .clone()
            .oneshot(json_with_token(method, uri, body, &self.token, &self.csrf))
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    /// The owner arms a full-auto job bound to `conversation_id`.
    async fn owner_job(&self, conversation_id: &str) -> String {
        let mut body = job_body(conversation_id);
        body["created_by"] = json!("user");
        body["agent_config"] = json!({ "name": "Cron Helper Assistant", "assistant_id": ASSISTANT_ID });
        let (status, json) = self.owner("POST", "/api/cron/jobs", body).await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        json["data"]["id"].as_str().unwrap().to_owned()
    }
}

fn assert_refused(status: StatusCode, json: &Value, code: &str) {
    assert_eq!(
        (status, json["code"].as_str()),
        (StatusCode::FORBIDDEN, Some(code)),
        "{json}"
    );
}

#[tokio::test]
async fn helper_creates_own_conversation_job_in_approval_mode() {
    let (f, services) = fixture().await;
    let (status, json) = f.helper("POST", "/api/cron/jobs", Some(job_body(OWN))).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["data"]["metadata"]["conversation_id"], OWN);
    // No forced mode: the run keeps the conversation's own approval mode.
    let mode = &json["data"]["metadata"]["agent_config"]["mode"];
    assert!(mode.is_null(), "helper job must not carry a full-auto mode, got {mode}");
    services.database.close().await;
}

#[tokio::test]
async fn helper_cannot_create_or_update_another_conversations_job() {
    let (f, services) = fixture().await;
    let (status, json) = f.helper("POST", "/api/cron/jobs", Some(job_body(OTHER))).await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");

    let foreign = f.owner_job(OTHER).await;
    let (status, json) = f
        .helper(
            "PUT",
            &format!("/api/cron/jobs/{foreign}"),
            Some(json!({ "name": "x" })),
        )
        .await;
    assert_eq!(
        (status, json["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("NOT_FOUND")),
        "{json}"
    );
    let (status, json) = f.helper("GET", &format!("/api/cron/jobs/{foreign}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
    let (status, json) = f.helper("GET", "/api/cron/jobs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().unwrap().len(), 0, "{json}");
    services.database.close().await;
}

#[tokio::test]
async fn helper_cannot_escalate_to_full_auto() {
    let (f, services) = fixture().await;
    let mut body = job_body(OWN);
    body["agent_config"] = json!({ "name": "x", "assistant_id": ASSISTANT_ID, "mode": "yolo" });
    let (status, json) = f.helper("POST", "/api/cron/jobs", Some(body)).await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");

    let mut body = job_body(OWN);
    body["execution_mode"] = json!("new_conversation");
    let (status, json) = f.helper("POST", "/api/cron/jobs", Some(body)).await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");

    let (status, json) = f.helper("POST", "/api/cron/jobs", Some(job_body(OWN))).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    let own = json["data"]["id"].as_str().unwrap().to_owned();
    let (status, json) = f
        .helper(
            "PUT",
            &format!("/api/cron/jobs/{own}"),
            Some(json!({ "execution_mode": "new_conversation" })),
        )
        .await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");

    // A full-auto job the owner armed on this conversation is not the helper's to run or change.
    let armed = f.owner_job(OWN).await;
    let (status, json) = f.helper("POST", &format!("/api/cron/jobs/{armed}/run"), None).await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");
    let (status, json) = f
        .helper("PUT", &format!("/api/cron/jobs/{armed}"), Some(json!({ "name": "x" })))
        .await;
    assert_refused(status, &json, "CRON_HELPER_SCOPE");
    services.database.close().await;
}

#[tokio::test]
async fn helper_cannot_run_or_delete_another_conversations_job() {
    let (f, services) = fixture().await;
    let foreign = f.owner_job(OTHER).await;
    for (method, uri) in [
        ("POST", format!("/api/cron/jobs/{foreign}/run")),
        ("DELETE", format!("/api/cron/jobs/{foreign}")),
        ("DELETE", format!("/api/cron/jobs/{foreign}/skill")),
    ] {
        let (status, json) = f.helper(method, &uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {json}");
    }
    let (status, json) = f
        .helper(
            "POST",
            &format!("/api/cron/jobs/{foreign}/skill"),
            Some(json!({ "content": "# x" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
    let (status, _) = f.owner("GET", &format!("/api/cron/jobs/{foreign}"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "the foreign job must survive");
    services.database.close().await;
}

#[tokio::test]
async fn owner_desktop_keeps_full_cron_access() {
    let (f, services) = fixture().await;
    let job = f.owner_job(OTHER).await;
    let (status, json) = f
        .owner("PUT", &format!("/api/cron/jobs/{job}"), json!({ "name": "renamed" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["name"], "renamed");
    assert!(json["data"]["metadata"]["agent_config"]["mode"].is_string(), "{json}");
    let (status, json) = f.owner("DELETE", &format!("/api/cron/jobs/{job}"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    services.database.close().await;
}

/// Jev 056: a password-only (device-less) session may only pause cron jobs, like a paired
/// phone; any other change is refused before the job is even looked up.
#[tokio::test]
async fn deviceless_session_may_only_pause_cron_jobs() {
    let (f, services) = fixture().await;
    let job = f.owner_job(OWN).await;
    let mut app = f.app.clone();
    let (bob, bob_csrf) = common::setup_and_login(&mut app, &services, "bob", "BobP@ssw0rd!").await;

    let resp = app
        .clone()
        .oneshot(json_with_token(
            "PUT",
            &format!("/api/cron/jobs/{job}"),
            json!({ "name": "renamed" }),
            &bob,
            &bob_csrf,
        ))
        .await
        .unwrap();
    let status = resp.status();
    let json = body_json(resp).await;
    assert_refused(status, &json, "CRON_DESKTOP_ONLY");

    // A pure pause passes the gate; the job belongs to the owner, so bob gets not-found.
    let resp = app
        .oneshot(json_with_token(
            "PUT",
            &format!("/api/cron/jobs/{job}"),
            json!({ "enabled": false }),
            &bob,
            &bob_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    services.database.close().await;
}
