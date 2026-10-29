//! Attention inbox (B05, ADR-018) through the real app: a mock agent's turns finish, fail or
//! wait on an approval, and the owner's inbox lists the live approvals and the unseen outcomes.
//! Covers dedup, a user stop (not attention), seen, restart (no resurrected approval), owner
//! isolation, the agent helper, auth and CSRF.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use aionui_ai_agent::agent_task::{AgentInstance, IAgentTask, IMockAgent};
use aionui_ai_agent::protocol::events::tool_call::ToolCallEventData;
use aionui_ai_agent::protocol::events::{ErrorEventData, FinishEventData, TextEventData};
use aionui_ai_agent::types::{BuildTaskOptions, SendMessageData};
use aionui_ai_agent::{
    AgentError, AgentStreamEvent, IWorkerTaskManager, RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
};
use aionui_api_types::AgentErrorCode;
use aionui_common::{AgentKillReason, AgentType, Confirmation, ConversationStatus, TimestampMs, now_ms};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tower::ServiceExt;

use common::{body_json, get_with_token, json_with_token, setup_and_login};

/// Ends each turn by the message text: `finish`, `fail`, or `ask` (waits on an approval until
/// cancelled, like a real agent blocked on a permission request).
struct ScriptedAgent {
    conversation_id: String,
    event_tx: broadcast::Sender<AgentStreamEvent>,
    pending: Mutex<Vec<Confirmation>>,
    last_activity: AtomicI64,
}

#[async_trait]
impl IAgentTask for ScriptedAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Acp
    }
    fn conversation_id(&self) -> &str {
        &self.conversation_id
    }
    fn workspace(&self) -> &str {
        ""
    }
    fn status(&self) -> Option<ConversationStatus> {
        Some(ConversationStatus::Running)
    }
    fn last_activity_at(&self) -> TimestampMs {
        self.last_activity.load(Ordering::Relaxed)
    }
    fn subscribe(&self) -> broadcast::Receiver<AgentStreamEvent> {
        self.event_tx.subscribe()
    }
    async fn send_message(&self, data: SendMessageData) -> Result<(), aionui_ai_agent::AgentSendError> {
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        match data.content.as_str() {
            "fail" => {
                let _ = self.event_tx.send(AgentStreamEvent::Error(ErrorEventData::legacy(
                    "boom",
                    Some(AgentErrorCode::AionuiInternalError),
                )));
            }
            "ask" => self.pending.lock().unwrap().push(Confirmation {
                id: "conf-1".into(),
                call_id: "call-1".into(),
                title: Some("Run a command".into()),
                action: Some("exec".into()),
                description: "ls".into(),
                command_type: None,
                options: vec![],
                questions: None,
            }),
            "work" => {
                // A command the agent reports running, then its own summary of the result.
                for status in ["running", "completed"] {
                    let call: ToolCallEventData = serde_json::from_value(json!({
                        "call_id": "exec-1",
                        "name": "Run flutter test",
                        "args": {"type": "commandExecution", "exit_code": null},
                        "status": status,
                    }))
                    .unwrap();
                    let _ = self.event_tx.send(AgentStreamEvent::ToolCall(call));
                }
                let _ = self.event_tx.send(AgentStreamEvent::Text(TextEventData {
                    content: "Done. All tests pass.".into(),
                }));
                let _ = self.event_tx.send(AgentStreamEvent::Finish(FinishEventData::default()));
            }
            _ => {
                let _ = self.event_tx.send(AgentStreamEvent::Finish(FinishEventData::default()));
            }
        }
        Ok(())
    }
    async fn cancel(&self) -> Result<(), AgentError> {
        self.pending.lock().unwrap().clear();
        let _ = self.event_tx.send(AgentStreamEvent::Finish(FinishEventData::default()));
        Ok(())
    }
    fn kill(&self, _reason: Option<AgentKillReason>) -> Result<(), AgentError> {
        Ok(())
    }
}

impl IMockAgent for ScriptedAgent {
    fn get_confirmations(&self) -> Vec<Confirmation> {
        self.pending.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct Tasks {
    agents: Mutex<HashMap<String, AgentInstance>>,
}

#[async_trait]
impl IWorkerTaskManager for Tasks {
    fn get_task(&self, conversation_id: &str) -> Option<AgentInstance> {
        self.agents.lock().unwrap().get(conversation_id).cloned()
    }
    async fn get_or_build_task(&self, conversation_id: &str, _: BuildTaskOptions) -> Result<AgentInstance, AgentError> {
        let mut agents = self.agents.lock().unwrap();
        let agent = agents.entry(conversation_id.to_owned()).or_insert_with(|| {
            AgentInstance::Mock(Arc::new(ScriptedAgent {
                conversation_id: conversation_id.to_owned(),
                event_tx: broadcast::channel(64).0,
                pending: Mutex::default(),
                last_activity: AtomicI64::new(now_ms()),
            }))
        });
        Ok(agent.clone())
    }
    fn kill(&self, conversation_id: &str, _: Option<AgentKillReason>) -> Result<(), AgentError> {
        self.agents.lock().unwrap().remove(conversation_id);
        Ok(())
    }
    fn kill_and_wait(
        &self,
        conversation_id: &str,
        reason: Option<AgentKillReason>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let _ = self.kill(conversation_id, reason);
        Box::pin(std::future::ready(()))
    }
    async fn clear(&self) {
        self.agents.lock().unwrap().clear();
    }
    fn active_count(&self) -> usize {
        self.agents.lock().unwrap().len()
    }
    fn active_conversation_ids(&self) -> Vec<String> {
        self.agents.lock().unwrap().keys().cloned().collect()
    }
    fn collect_idle(&self, _: TimestampMs) -> Vec<String> {
        vec![]
    }
}

struct Host {
    app: Router,
    services: aionui_app::AppServices,
    tasks: Arc<Tasks>,
    token: String,
    csrf: String,
    workspace: tempfile::TempDir,
}

async fn host() -> Host {
    let tasks = Arc::new(Tasks::default());
    let db = aionui_db::init_database_memory().await.unwrap();
    let services = aionui_app::AppServices::from_config(db, &aionui_app::AppConfig::default())
        .await
        .unwrap()
        .with_worker_task_manager(tasks.clone());
    let mut app = aionui_app::create_router(&services).await.expect("router");
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    Host {
        app,
        services,
        tasks,
        token,
        csrf,
        workspace: tempfile::tempdir().unwrap(),
    }
}

impl Host {
    async fn call(&self, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .app
            .clone()
            .oneshot(json_with_token(method, uri, body, &self.token, &self.csrf))
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn conversation(&self, name: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/api/conversations",
                json!({"type": "acp", "name": name, "extra": {"workspace": self.workspace.path()}}),
            )
            .await;
        assert!(status.is_success(), "create: {status} {body}");
        body["data"]["id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, id: &str, content: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                &format!("/api/conversations/{id}/messages"),
                json!({"content": content}),
            )
            .await;
        assert!(status.is_success(), "send: {status} {body}");
        body["data"]["turn_id"].as_str().unwrap().to_owned()
    }

    async fn inbox_as(&self, token: &str) -> (StatusCode, Value) {
        let resp = self
            .app
            .clone()
            .oneshot(get_with_token("/api/inbox", token))
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn inbox(&self) -> Value {
        let (status, body) = self.inbox_as(&self.token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["data"].clone()
    }

    /// Polls until `check` holds on the inbox (turns end on background tasks).
    async fn inbox_until(&self, what: &str, check: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..100 {
            let inbox = self.inbox().await;
            if check(&inbox) {
                return inbox;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("inbox never showed {what}: {}", self.inbox().await);
    }
}

fn outcomes_of(inbox: &Value, conversation_id: &str) -> Vec<Value> {
    inbox["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["conversation_id"] == conversation_id)
        .cloned()
        .collect()
}

#[tokio::test]
async fn finished_and_failed_turns_are_listed_once_until_the_chat_is_seen() {
    let h = host().await;
    let mut events = h.services.event_bus.subscribe();
    let done = h.conversation("done chat").await;
    let broken = h.conversation("broken chat").await;

    let ok_turn = h.send(&done, "finish").await;
    let fail_turn = h.send(&broken, "fail").await;
    let inbox = h
        .inbox_until("both outcomes", |i| i["outcomes"].as_array().unwrap().len() == 2)
        .await;

    let ok = outcomes_of(&inbox, &done);
    assert_eq!(ok.len(), 1, "one row per turn: {inbox}");
    assert_eq!(ok[0]["turn_id"], ok_turn.as_str());
    assert_eq!(ok[0]["outcome"], "finished");
    assert_eq!(ok[0]["source"], "relay_finish");
    assert_eq!(ok[0]["conversation_name"], "done chat");

    let failed = outcomes_of(&inbox, &broken);
    assert_eq!(failed.len(), 1, "{inbox}");
    assert_eq!(failed[0]["turn_id"], fail_turn.as_str());
    assert_eq!(failed[0]["outcome"], "failed");
    assert_eq!(failed[0]["source"], "relay_error");
    assert_eq!(failed[0]["error_code"], "AIONUI_INTERNAL_ERROR");
    assert!(
        !inbox.to_string().contains("boom"),
        "no error text in the inbox: {inbox}"
    );

    // The client is told to re-read, with only ids in the payload.
    let mut changed = Vec::new();
    while let Ok(event) = events.try_recv() {
        if event.name == "inbox.changed" {
            changed.push(event.data);
        }
    }
    assert!(
        changed
            .iter()
            .any(|d| d["conversation_id"] == broken.as_str() && d["user_id"].is_string()),
        "{changed:?}"
    );
    assert!(changed.iter().all(|d| d.as_object().unwrap().len() == 2), "{changed:?}");

    // Opening the chat clears it from the inbox; the other stays.
    let (status, body) = h
        .call("POST", "/api/inbox/seen", json!({"conversation_id": done}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let inbox = h.inbox().await;
    assert!(outcomes_of(&inbox, &done).is_empty(), "{inbox}");
    assert_eq!(outcomes_of(&inbox, &broken).len(), 1);

    // A new turn in the seen chat shows up again.
    h.send(&done, "finish").await;
    h.inbox_until("the new turn", |i| outcomes_of(i, &done).len() == 1)
        .await;
}

#[tokio::test]
async fn a_waiting_approval_is_listed_live_and_a_user_stop_is_not_attention() {
    let h = host().await;
    let id = h.conversation("needs approval").await;
    let turn = h.send(&id, "ask").await;

    let inbox = h
        .inbox_until("the approval", |i| !i["approvals"].as_array().unwrap().is_empty())
        .await;
    let approvals = inbox["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1, "{inbox}");
    assert_eq!(approvals[0]["conversation_id"], id.as_str());
    assert_eq!(approvals[0]["conversation_name"], "needs approval");
    assert_eq!(approvals[0]["confirmation"]["call_id"], "call-1");
    // Reading the inbox twice is not two items, and starts nothing new.
    assert_eq!(h.inbox().await["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(h.tasks.active_count(), 1);

    let (status, body) = h
        .call(
            "POST",
            &format!("/api/conversations/{id}/cancel"),
            json!({"turn_id": turn}),
        )
        .await;
    assert!(status.is_success(), "cancel: {status} {body}");

    // The approval is gone and the stopped turn is not listed, even after its relay finished.
    let inbox = h
        .inbox_until("no approval", |i| i["approvals"].as_array().unwrap().is_empty())
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let inbox_after = h.inbox().await;
    assert!(outcomes_of(&inbox, &id).is_empty(), "{inbox}");
    assert!(
        outcomes_of(&inbox_after, &id).is_empty(),
        "stop must win: {inbox_after}"
    );
    let stored: Option<String> = sqlx::query_scalar("SELECT outcome FROM turn_outcomes WHERE turn_id = ?")
        .bind(&turn)
        .fetch_optional(h.services.database.pool())
        .await
        .unwrap();
    assert_eq!(stored.as_deref(), Some("stopped"));
}

#[tokio::test]
async fn an_approval_does_not_outlive_its_agent() {
    let h = host().await;
    let id = h.conversation("restart").await;
    h.send(&id, "ask").await;
    h.inbox_until("the approval", |i| !i["approvals"].as_array().unwrap().is_empty())
        .await;

    // A host restart ends every agent process; nothing can execute the old approval.
    h.tasks.clear().await;
    let inbox = h.inbox().await;
    assert!(inbox["approvals"].as_array().unwrap().is_empty(), "{inbox}");
}

#[tokio::test]
async fn another_user_sees_nothing_of_the_owner() {
    let h = host().await;
    let id = h.conversation("private").await;
    h.send(&id, "fail").await;
    let other = h.conversation("waiting").await;
    h.send(&other, "ask").await;
    h.inbox_until("owner items", |i| {
        !i["outcomes"].as_array().unwrap().is_empty() && !i["approvals"].as_array().unwrap().is_empty()
    })
    .await;

    let mut app = h.app.clone();
    let (bob, bob_csrf) = setup_and_login(&mut app, &h.services, "bob", "StrongP@ss2").await;
    let (status, body) = h.inbox_as(&bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], json!({"approvals": [], "outcomes": []}));

    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/inbox/seen",
            json!({"conversation_id": id}),
            &bob,
            &bob_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        outcomes_of(&h.inbox().await, &id).len(),
        1,
        "bob cannot clear the owner's inbox"
    );
}

#[tokio::test]
async fn the_inbox_needs_a_session_csrf_and_is_not_for_the_agent_helper() {
    let h = host().await;
    let id = h.conversation("guarded").await;

    let resp = h
        .app
        .clone()
        .oneshot(Request::builder().uri("/api/inbox").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/inbox/seen")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::from(json!({"conversation_id": id}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "seen without CSRF");

    let (status, body) = h
        .call("POST", "/api/inbox/seen", json!({"conversation_id": "missing"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = h.call("POST", "/api/inbox/seen", json!({})).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("BAD_REQUEST"))
    );

    let owner = h
        .services
        .user_repo
        .find_by_username("admin")
        .await
        .unwrap()
        .unwrap()
        .id;
    common::ensure_conversation(&h.services, owner.as_str(), id.as_str()).await;
    let issue = h.services.runtime_token_service.issue(
        owner.as_str(),
        id.as_str(),
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/inbox")
                .header("x-aionui-runtime-token", issue.token.as_str())
                .header("x-aionui-user-id", owner.as_str())
                .header("x-aionui-conversation-id", id.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "INBOX_OWNER_ONLY");
}

/// B05.R1: the receipt keeps the host's observations (outcome, folder state) apart from the
/// agent's claims (its tool report and its summary) and from the owner's acceptance.
#[tokio::test]
async fn a_receipt_separates_host_observations_agent_claims_and_acceptance() {
    let h = host().await;
    let repo = git2::Repository::init(h.workspace.path()).unwrap();
    std::fs::write(h.workspace.path().join("lib.dart"), "void main() {}").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("lib.dart")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = git2::Signature::now("t", "t@example.com").unwrap();
    let head = repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[]).unwrap();

    let id = h.conversation("receipt").await;
    let turn = h.send(&id, "work").await;
    h.inbox_until("the outcome", |i| outcomes_of(i, &id).len() == 1).await;
    let uri = format!("/api/conversations/{id}/turns/{turn}/receipt");
    let mut receipt = Value::Null;
    for _ in 0..100 {
        let (status, body) = h.call("GET", &uri, Value::Null).await;
        if status == StatusCode::OK {
            receipt = body["data"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(receipt["outcome"], "finished", "{receipt}");
    assert_eq!(receipt["source"], "relay_finish");
    assert!(receipt["started_at"].as_i64().unwrap() <= receipt["ended_at"].as_i64().unwrap());
    // Agent claims, labelled as such: no exit code was reported, so none is made up.
    assert_eq!(
        receipt["tools"],
        json!([{"call_id": "exec-1", "name": "Run flutter test", "status": "completed", "reported_exit_code": null}])
    );
    assert_eq!(receipt["agent_claim"], "Done. All tests pass.");
    // Host observation of the folder: unchanged since the turn ended.
    assert_eq!(
        receipt["workspace"],
        json!({"state": "git", "head": head.to_string(), "stale": false})
    );
    assert_eq!(receipt["accepted_at"], Value::Null);

    // An edit after the turn makes its evidence stale.
    std::fs::write(h.workspace.path().join("lib.dart"), "void main() { print(1); }").unwrap();
    let (_, body) = h.call("GET", &uri, Value::Null).await;
    assert_eq!(body["data"]["workspace"]["stale"], true);

    // Acceptance is recorded once and changes nothing else.
    let (status, body) = h.call("POST", &format!("{uri}/accept"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let accepted = body["data"]["accepted_at"].as_i64().expect("accepted");
    assert_eq!(body["data"]["tools"], receipt["tools"]);
    let (_, again) = h.call("POST", &format!("{uri}/accept"), json!({})).await;
    assert_eq!(again["data"]["accepted_at"].as_i64(), Some(accepted));
}

#[tokio::test]
async fn a_receipt_is_the_owners_only_and_needs_a_known_turn() {
    let h = host().await;
    let id = h.conversation("plain folder").await;
    let turn = h.send(&id, "finish").await;
    h.inbox_until("the outcome", |i| outcomes_of(i, &id).len() == 1).await;
    let uri = format!("/api/conversations/{id}/turns/{turn}/receipt");
    let mut body = Value::Null;
    for _ in 0..100 {
        let (status, b) = h.call("GET", &uri, Value::Null).await;
        body = b;
        if status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Not a git work tree: nothing to compare, and the receipt says so.
    assert_eq!(
        body["data"]["workspace"],
        json!({"state": "not_git", "head": null, "stale": null}),
        "{body}"
    );
    assert_eq!(body["data"]["tools"], json!([]));

    let (status, body) = h
        .call(
            "GET",
            &format!("/api/conversations/{id}/turns/turn_missing/receipt"),
            Value::Null,
        )
        .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("RECEIPT_NOT_FOUND"))
    );
    let (status, _) = h
        .call(
            "POST",
            &format!("/api/conversations/{id}/turns/turn_missing/receipt/accept"),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mut app = h.app.clone();
    let (bob, bob_csrf) = setup_and_login(&mut app, &h.services, "bob", "StrongP@ss2").await;
    let resp = app.clone().oneshot(get_with_token(&uri, &bob)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("{uri}/accept"),
            json!({}),
            &bob,
            &bob_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{uri}/accept"))
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "accept without CSRF");
    let resp = h
        .app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
