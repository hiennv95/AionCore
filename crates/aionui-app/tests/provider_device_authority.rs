//! Model providers hold API keys and drive host outbound requests (Jev 047, as for MCP).
//! Paired phones and browsers and the agent helper list providers with secrets masked, and
//! are refused (403 `PROVIDERS_DESKTOP_ONLY`) on every route that changes a provider, makes
//! the host call a caller-chosen URL, or installs a runtime. The desktop app keeps full access.

mod common;

use std::time::Duration;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, desktop_and_phone, json_with_token};

const KEY: &str = "sk-desktop-only-key-123";
const AWS_SECRET: &str = "aws-secret-access-key-456";

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn desktop_only_routes(provider: &str, target: &str) -> Vec<(&'static str, String, Value)> {
    vec![
        (
            "POST",
            "/api/providers".into(),
            json!({"platform": "openai", "name": "device added", "base_url": target, "api_key": "x"}),
        ),
        ("PUT", format!("/api/providers/{provider}"), json!({"name": "renamed"})),
        ("DELETE", format!("/api/providers/{provider}"), json!({})),
        ("POST", format!("/api/providers/{provider}/models"), json!({})),
        (
            "POST",
            "/api/providers/fetch-models".into(),
            json!({"platform": "openai", "base_url": target, "api_key": "x"}),
        ),
        (
            "POST",
            "/api/providers/detect-protocol".into(),
            json!({"base_url": target, "api_key": "x"}),
        ),
        (
            "POST",
            "/api/system/ensure-node-runtime".into(),
            json!({"scope": "builtin"}),
        ),
    ]
}

#[tokio::test]
async fn paired_devices_and_the_helper_see_masked_providers_and_cannot_change_or_probe_them() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, _) = build_app_with_skill_paths(tmp.path()).await;
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };

    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;

    // The desktop creates an API-key provider and a Bedrock access-key provider.
    let (status, created) = send(json_with_token(
        "POST",
        "/api/providers",
        json!({"platform": "openai", "name": "openai", "base_url": "https://api.example.invalid", "api_key": KEY}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let provider = created["data"]["id"].as_str().unwrap().to_owned();
    let (status, created) = send(json_with_token(
        "POST",
        "/api/providers",
        json!({
            "platform": "bedrock", "name": "bedrock", "base_url": "", "api_key": "",
            "bedrock_config": {"auth_method": "accessKey", "region": "us-east-1",
                "access_key_id": "AKIAEXAMPLE", "secret_access_key": AWS_SECRET}
        }),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    // The desktop reads full values.
    let (status, list) = send(get("/api/providers", &desktop)).await;
    assert_eq!(status, StatusCode::OK);
    let text = list.to_string();
    assert!(text.contains(KEY) && text.contains(AWS_SECRET), "{text}");

    // The phone lists the same providers with every secret masked.
    let (status, list) = send(get("/api/providers", &phone)).await;
    assert_eq!(status, StatusCode::OK);
    let text = list.to_string();
    assert!(
        !text.contains(KEY) && !text.contains(AWS_SECRET) && !text.contains("AKIAEXAMPLE"),
        "{text}"
    );
    let items = list["data"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let openai = items.iter().find(|p| p["name"] == "openai").unwrap();
    assert_eq!(openai["api_key"], "***");
    assert_eq!(openai["base_url"], "https://api.example.invalid");
    let bedrock = items.iter().find(|p| p["name"] == "bedrock").unwrap();
    assert_eq!(bedrock["api_key"], "", "an empty key stays empty");
    assert_eq!(bedrock["bedrock_config"]["access_key_id"], "***");
    assert_eq!(bedrock["bedrock_config"]["secret_access_key"], "***");
    assert_eq!(bedrock["bedrock_config"]["region"], "us-east-1");

    // A listener stands in for an internal service the phone would like the host to call.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_url = format!("http://{}", target.local_addr().unwrap());

    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-providers",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let refused = json!("PROVIDERS_DESKTOP_ONLY");
    for (method, uri, body) in desktop_only_routes(&provider, &target_url) {
        let (status, resp) = send(json_with_token(method, &uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {method} {uri}: {resp}"
        );
        let req = Request::builder()
            .method(method)
            .uri(&uri)
            .header("content-type", "application/json")
            .header("x-aionui-runtime-token", helper.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-providers")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, resp) = send(req).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "helper {method} {uri}: {resp}"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), target.accept())
            .await
            .is_err(),
        "the host connected to the phone's chosen URL"
    );

    // Nothing changed: the provider is still there with its key.
    let (_, list) = send(get("/api/providers", &desktop)).await;
    let openai = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == provider.as_str())
        .cloned();
    assert_eq!(openai.unwrap()["api_key"], KEY);

    // The desktop still manages providers.
    let (status, resp) = send(json_with_token(
        "PUT",
        &format!("/api/providers/{provider}"),
        json!({"name": "renamed on desktop"}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["data"]["api_key"], KEY);
    let (status, resp) = send(json_with_token(
        "POST",
        "/api/providers/fetch-models",
        json!({"platform": "openai", "base_url": "http://127.0.0.1:9", "api_key": "x"}),
        &desktop,
        "c",
    ))
    .await;
    assert_ne!(resp["code"], refused, "{status} {resp}");
}
