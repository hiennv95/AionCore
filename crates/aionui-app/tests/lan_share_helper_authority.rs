//! A LAN share grants a peer chat with one agent (ADR-009), not owner configuration. The
//! agent process of a LAN-share conversation still receives the helper credential, so the
//! host refuses that credential everywhere except read-only skill listing and reading
//! (owner decision on Jev 051). Owner conversations keep their helper. The credential used
//! here is the one the (mock) agent was actually built with.

mod common;

use aionui_api_types::{ConversationToolErrorCode, SessionToolErrorCode};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_capturing_mock_agents_at, desktop_and_phone, json_with_token};

const REFUSED: &str = "HELPER_NOT_FOR_LAN_SHARE";

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), body_json(resp).await)
}

fn as_helper(
    method: &str,
    uri: &str,
    body: Option<&Value>,
    token: &str,
    owner: &str,
    conversation: &str,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-aionui-runtime-token", token)
        .header("x-aionui-user-id", owner)
        .header("x-aionui-conversation-id", conversation);
    match body {
        Some(body) => builder.body(Body::from(body.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Both conversations, and the helper token each one's (mock) agent was built with.
struct Shares {
    _tmp: tempfile::TempDir,
    app: axum::Router,
    services: aionui_app::AppServices,
    desktop: String,
    owner: String,
    lan: String,
    mine: String,
    lan_token: String,
    my_token: String,
}

async fn shares() -> Shares {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, captured) = build_app_with_capturing_mock_agents_at(tmp.path()).await;
    let (desktop, _phone) = desktop_and_phone(&app, tmp.path()).await;
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;

    // A LAN-share conversation exactly as the network runner creates it, and an owner one.
    let lan = services
        .conversation_service
        .create(
            owner.as_str(),
            aionui_api_types::CreateConversationRequest {
                r#type: Some(aionui_common::AgentType::Acp),
                name: Some("peer share".into()),
                model: None,
                assistant: None,
                source: Some(aionui_common::ConversationSource::Aionui),
                channel_chat_id: None,
                extra: json!({
                    "backend": "gemini",
                    "workspace": tmp.path().to_string_lossy(),
                    "session_mode": "default",
                    "current_mode_id": "default",
                    "lan_remote": true,
                }),
            },
        )
        .await
        .unwrap()
        .id;
    let (status, created) = send(
        &app,
        json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "owner chat", "extra": {"backend": "gemini"}}),
            &desktop,
            "c",
        ),
    )
    .await;
    assert!(status.is_success(), "{status} {created}");
    let mine = created["data"]["id"].as_str().unwrap().to_owned();

    // Build both agents and take the helper token each one was given.
    for conversation in [&lan, &mine] {
        services
            .conversation_service
            .warmup(owner.as_str(), conversation, &services.worker_task_manager)
            .await
            .unwrap();
    }
    let token_of = |conversation: &str| {
        captured.lock().unwrap()[conversation]
            .iter()
            .find(|(key, _)| key == "AIONUI_RUNTIME_TOKEN")
            .map(|(_, value)| value.clone())
            .expect("the agent received a helper token")
    };
    let lan_token = token_of(&lan);
    let my_token = token_of(&mine);
    Shares {
        _tmp: tmp,
        app,
        services,
        desktop,
        owner: owner.to_string(),
        lan,
        mine,
        lan_token,
        my_token,
    }
}

#[tokio::test]
async fn a_lan_share_agent_helper_only_reads_skills() {
    let Shares {
        app,
        desktop,
        owner,
        lan,
        mine,
        lan_token,
        my_token,
        ..
    } = shares().await;

    let assistant = json!({"id": "from-helper", "name": "From helper", "agent_id": "632f31d2", "avatar": "🤖"});
    let writes_and_reads = [
        ("POST", "/api/assistants", Some(assistant.clone())),
        ("GET", "/api/assistants", None),
        ("POST", "/api/cron/jobs", Some(json!({}))),
        ("GET", "/api/mcp/servers", None),
    ];
    for (method, uri, body) in &writes_and_reads {
        let (status, resp) = send(
            &app,
            as_helper(method, uri, body.as_ref(), &lan_token, owner.as_str(), &lan),
        )
        .await;
        assert_eq!(
            (status, resp["code"].clone()),
            (StatusCode::FORBIDDEN, json!(REFUSED)),
            "LAN-share helper {method} {uri}: {resp}"
        );
    }
    let (_, list) = send(
        &app,
        json_with_token("GET", "/api/assistants", json!({}), &desktop, "c"),
    )
    .await;
    assert!(!list.to_string().contains("from-helper"), "nothing was created");

    // Read-only skills stay open to it.
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/runtime/skills", None, &lan_token, owner.as_str(), &lan),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "LAN-share helper lists skills: {resp}");

    // The owner conversation's helper is unchanged.
    let (status, resp) = send(
        &app,
        as_helper(
            "POST",
            "/api/assistants",
            Some(&assistant),
            &my_token,
            owner.as_str(),
            &mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner helper writes: {resp}");
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/runtime/skills", None, &my_token, owner.as_str(), &mine),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner helper lists skills: {resp}");
}

/// The routes that authenticate the helper themselves, outside the auth middleware,
/// apply the same rule.
#[tokio::test]
async fn self_authenticating_helper_routes_refuse_a_lan_share() {
    let Shares {
        app,
        owner,
        lan,
        mine,
        lan_token,
        my_token,
        ..
    } = shares().await;
    let create = json!({"name": "spawned by helper"});
    let message = json!({"to": mine, "message": "hello"});
    // The codes the agent's `capabilities` document (serialized from the same enums).
    let conversation_code = serde_json::to_value(ConversationToolErrorCode::HelperNotForLanShare).unwrap();
    let session_code = serde_json::to_value(SessionToolErrorCode::HelperNotForLanShare).unwrap();
    let routes = [
        (
            "POST",
            "/api/runtime/conversations/create",
            Some(&create),
            &conversation_code,
        ),
        (
            "POST",
            "/api/runtime/session-messages/send",
            Some(&message),
            &session_code,
        ),
        ("GET", "/api/runtime/session-messages/targets", None, &session_code),
    ];
    for (method, uri, body, code) in routes {
        let (status, resp) = send(&app, as_helper(method, uri, body, &lan_token, owner.as_str(), &lan)).await;
        assert_eq!(
            (status, resp["error"]["code"].clone()),
            (StatusCode::FORBIDDEN, code.clone()),
            "LAN-share helper {method} {uri}: {resp}"
        );
    }

    // The owner conversation's helper still lists targets.
    let (status, resp) = send(
        &app,
        as_helper(
            "GET",
            "/api/runtime/session-messages/targets",
            None,
            &my_token,
            owner.as_str(),
            &mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner helper lists targets: {resp}");
}

/// The token is bound to its own conversation: the headers cannot move it to another
/// one, in either direction, on any helper channel.
#[tokio::test]
async fn helper_headers_cannot_rebind_a_token() {
    let Shares {
        app,
        owner,
        lan,
        mine,
        lan_token,
        my_token,
        ..
    } = shares().await;
    for (token, conversation) in [(&lan_token, &mine), (&my_token, &lan)] {
        let (status, _) = send(
            &app,
            as_helper("GET", "/api/assistants", None, token, owner.as_str(), conversation),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "middleware channel");
        for uri in ["/api/runtime/skills", "/api/runtime/session-messages/targets"] {
            let (status, resp) = send(&app, as_helper("GET", uri, None, token, owner.as_str(), conversation)).await;
            assert_eq!(
                (status, resp["error"]["code"].clone()),
                (StatusCode::UNAUTHORIZED, json!("runtime_auth_failed")),
                "{uri}: {resp}"
            );
        }
    }
}

/// Reads stay limited to the skill routes and to this conversation's enabled skills.
#[tokio::test]
async fn a_lan_share_reads_only_its_enabled_skills() {
    let Shares {
        app,
        owner,
        lan,
        lan_token,
        ..
    } = shares().await;
    // The ordinary skill API is not a runtime skill route.
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/skills", None, &lan_token, owner.as_str(), &lan),
    )
    .await;
    assert_eq!(
        (status, resp["code"].clone()),
        (StatusCode::FORBIDDEN, json!(REFUSED)),
        "GET /api/skills: {resp}"
    );
    for uri in [
        "/api/runtime/skills/not-enabled",
        "/api/runtime/skills/not-enabled/file?path=../../etc/passwd",
    ] {
        let (status, resp) = send(&app, as_helper("GET", uri, None, &lan_token, owner.as_str(), &lan)).await;
        assert_ne!(status, StatusCode::OK, "{uri}");
        assert_eq!(resp["error"]["code"], json!("skill_not_enabled"), "{uri}: {resp}");
    }
}

/// The rule is checked on every request, so a token the agent already holds follows
/// what its conversation is now.
#[tokio::test]
async fn an_issued_token_follows_its_conversation_becoming_a_share() {
    let Shares {
        app,
        services,
        owner,
        mine,
        my_token,
        ..
    } = shares().await;
    let list = || as_helper("GET", "/api/assistants", None, &my_token, owner.as_str(), &mine);
    let (status, resp) = send(&app, list()).await;
    assert_eq!(status, StatusCode::OK, "before: {resp}");

    services
        .conversation_repo
        .update(
            owner.as_str(),
            &mine,
            &aionui_db::ConversationRowUpdate {
                extra: Some(json!({"backend": "gemini", "lan_remote": true}).to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (status, resp) = send(&app, list()).await;
    assert_eq!(
        (status, resp["code"].clone()),
        (StatusCode::FORBIDDEN, json!(REFUSED)),
        "after: {resp}"
    );
}

/// A LAN share reads the skills its conversation enabled, and the skill routes keep
/// their containment for it: no `..`, no link out of the skill directory.
#[tokio::test]
async fn a_lan_share_reads_an_enabled_skill_inside_its_directory_only() {
    let Shares {
        _tmp: tmp,
        app,
        services,
        owner,
        ..
    } = shares().await;
    let skill = services
        .skill_paths
        .builtin_skills_dir
        .join("auto-inject")
        .join("lan-skill");
    std::fs::create_dir_all(skill.join("refs")).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: lan-skill\ndescription: d\n---\nlan skill body",
    )
    .unwrap();
    std::fs::write(skill.join("refs").join("note.md"), "inside the skill").unwrap();
    let outside = tmp.path().join("outside-secret.txt");
    std::fs::write(&outside, "host secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, skill.join("link.txt")).unwrap();

    let share = "conv-lan-skill";
    let extra = json!({"backend": "gemini", "lan_remote": true, "skills": ["lan-skill"]});
    common::ensure_conversation(&services, &owner, share).await;
    services
        .conversation_repo
        .update(
            &owner,
            share,
            &aionui_db::ConversationRowUpdate {
                extra: Some(extra.to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let token = services
        .runtime_token_service
        .issue(
            owner.as_str(),
            share,
            aionui_ai_agent::TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
            [aionui_ai_agent::RuntimeTokenScope::ConversationHelper],
        )
        .token;
    let get = |uri: &str| as_helper("GET", uri, None, &token, owner.as_str(), share);

    let (status, resp) = send(&app, get("/api/runtime/skills/lan-skill")).await;
    assert_eq!(status, StatusCode::OK, "show: {resp}");
    assert!(resp.to_string().contains("lan skill body"), "{resp}");
    let (status, resp) = send(&app, get("/api/runtime/skills/lan-skill/file?path=refs/note.md")).await;
    assert_eq!(status, StatusCode::OK, "file: {resp}");
    assert!(resp.to_string().contains("inside the skill"), "{resp}");

    let mut refused = vec!["/api/runtime/skills/lan-skill/file?path=../../outside-secret.txt"];
    if cfg!(unix) {
        refused.push("/api/runtime/skills/lan-skill/file?path=link.txt");
    }
    for uri in refused {
        let (status, resp) = send(&app, get(uri)).await;
        assert_ne!(status, StatusCode::OK, "{uri}");
        assert_eq!(resp["error"]["code"], json!("invalid_path"), "{uri}: {resp}");
        assert!(!resp.to_string().contains("host secret"), "{uri}: {resp}");
    }

    // The same token still writes nothing.
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/assistants", None, &token, owner.as_str(), share),
    )
    .await;
    assert_eq!(
        (status, resp["code"].clone()),
        (StatusCode::FORBIDDEN, json!(REFUSED)),
        "{resp}"
    );
}
