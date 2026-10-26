//! Two-host harness: each host has its own in-memory DB, identity, and a real
//! mutual-TLS peer listener on loopback. The agent runtime is a scripted fake.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aionui_api_types::{OutboundRequestView, PeerState, UpdateNetworkSettingsRequest};
use aionui_db::{Database, INetworkRepository, SqliteNetworkRepository, init_database_memory};
use aionui_network::{
    HostContext, HttpsPeerTransport, InboundService, NetworkError, NetworkService, OutboundService,
    RemoteConversationSpec, RemoteTurnRunner, TurnEvent,
};
use tokio::sync::mpsc;

pub const OWNER: &str = "owner";

#[derive(Default)]
pub struct FakeRunner {
    pub created: Mutex<Vec<RemoteConversationSpec>>,
    pub turns: Mutex<Vec<(String, String)>>,
    pub cancelled: Mutex<Vec<String>>,
    senders: Mutex<HashMap<String, mpsc::Sender<TurnEvent>>>,
}

impl FakeRunner {
    pub fn turn_count(&self) -> usize {
        self.turns.lock().unwrap().len()
    }

    /// Push an event into the running turn of `conversation_id`.
    pub async fn emit(&self, conversation_id: &str, event: TurnEvent) {
        let sender = self.senders.lock().unwrap().get(conversation_id).cloned();
        sender.expect("turn running").send(event).await.unwrap();
    }

    pub fn last_conversation(&self) -> String {
        self.turns.lock().unwrap().last().expect("a turn").0.clone()
    }
}

#[async_trait::async_trait]
impl RemoteTurnRunner for FakeRunner {
    async fn create_conversation(&self, _owner: &str, spec: &RemoteConversationSpec) -> Result<String, NetworkError> {
        let mut created = self.created.lock().unwrap();
        created.push(spec.clone());
        Ok(format!("conv-{}", created.len()))
    }

    async fn start_turn(
        &self,
        _owner: &str,
        conversation_id: &str,
        content: &str,
    ) -> Result<mpsc::Receiver<TurnEvent>, NetworkError> {
        let (tx, rx) = mpsc::channel(16);
        self.senders.lock().unwrap().insert(conversation_id.to_owned(), tx);
        self.turns
            .lock()
            .unwrap()
            .push((conversation_id.to_owned(), content.to_owned()));
        Ok(rx)
    }

    async fn cancel_turn(&self, _owner: &str, conversation_id: &str) -> Result<(), NetworkError> {
        self.cancelled.lock().unwrap().push(conversation_id.to_owned());
        Ok(())
    }
}

pub struct TestHost {
    pub service: Arc<NetworkService>,
    pub inbound: Arc<InboundService>,
    pub repo: Arc<dyn INetworkRepository>,
    pub host: Arc<HostContext>,
    pub runner: Arc<FakeRunner>,
    pub port: u16,
    pub _db: Database,
    pub _dir: tempfile::TempDir,
}

impl TestHost {
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    pub async fn set_listening(&self, enabled: bool) {
        self.service
            .update_settings(
                OWNER,
                UpdateNetworkSettingsRequest {
                    enabled: Some(enabled),
                    listen_port: Some(self.port),
                    display_name: None,
                },
            )
            .await
            .unwrap();
    }

    pub async fn peer_id_of(&self, other: &TestHost) -> String {
        self.repo
            .find_peer_by_fingerprint(other.host.fingerprint().as_str())
            .await
            .unwrap()
            .expect("peer known")
            .id
    }

    pub async fn outbound(&self, id: &str) -> OutboundRequestView {
        self.service.get_outbound(OWNER, id).await.unwrap()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub async fn start_host(name: &str) -> TestHost {
    let dir = tempfile::tempdir().unwrap();
    let db = init_database_memory().await.unwrap();
    let repo: Arc<dyn INetworkRepository> = Arc::new(SqliteNetworkRepository::new(db.pool().clone()));
    build_host(name, dir, db, repo).await
}

pub async fn build_host(
    name: &str,
    dir: tempfile::TempDir,
    db: Database,
    repo: Arc<dyn INetworkRepository>,
) -> TestHost {
    let host = Arc::new(HostContext::load(&dir.path().join("peer"), OWNER.into(), dir.path().join("ws")).unwrap());
    let runner = Arc::new(FakeRunner::default());
    let transport = Arc::new(HttpsPeerTransport::new(host.identity().clone()));
    let inbound = Arc::new(InboundService::new(repo.clone(), runner.clone(), host.clone()));
    let outbound = Arc::new(OutboundService::new(repo.clone(), transport.clone()));
    let service = Arc::new(NetworkService::new(
        repo.clone(),
        host.clone(),
        inbound.clone(),
        outbound,
        transport,
    ));
    service.start(None).await.unwrap();
    let test_host = TestHost {
        service,
        inbound,
        repo,
        host,
        runner,
        port: free_port(),
        _db: db,
        _dir: dir,
    };
    test_host
        .service
        .update_settings(
            OWNER,
            UpdateNetworkSettingsRequest {
                enabled: Some(true),
                listen_port: Some(test_host.port),
                display_name: Some(name.into()),
            },
        )
        .await
        .unwrap();
    test_host
}

/// Pair `a` → `b` and have both owners approve.
pub async fn pair(a: &TestHost, b: &TestHost) {
    let view = a
        .service
        .add_peer(OWNER, aionui_api_types::AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    assert_eq!(view.state, PeerState::PendingOutbound);
    let on_b = b.peer_id_of(a).await;
    b.service.approve_peer(OWNER, &on_b).await.unwrap();
    a.service.approve_peer(OWNER, &view.id).await.unwrap();
}

/// Poll `check` until it returns `Some`, up to 10 s.
pub async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
