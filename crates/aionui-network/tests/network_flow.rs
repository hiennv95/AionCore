mod support;

use aionui_api_types::{
    AddPeerRequest, CreateShareRequest, PEER_CONTRACT_VERSION, PeerState, PeerSubmitRequest, RemoteRequestState,
    SendRemoteRequest, WaitingKind,
};
use aionui_common::now_ms;
use aionui_db::{InsertInboundParams, RequestUpdate};
use aionui_network::{HttpsPeerTransport, NetworkError, PeerTransport, TurnEvent};
use support::{OWNER, TestHost, eventually, pair, start_host};

#[tokio::test]
async fn lan_outbox_restart_child() {
    let Ok(dir) = std::env::var("AIONX_TEST_RESTART_DIR") else { return };
    let port: u16 = std::env::var("AIONX_TEST_RESTART_PORT").unwrap().parse().unwrap();
    let path = std::path::Path::new(&dir);
    let db = aionui_db::init_database(&path.join("host.sqlite")).await.unwrap();
    let repo: std::sync::Arc<dyn aionui_db::INetworkRepository> = std::sync::Arc::new(aionui_db::SqliteNetworkRepository::new(db.pool().clone()));
    let host = std::sync::Arc::new(aionui_network::HostContext::load(&path.join("peer"), OWNER.into(), path.join("ws")).unwrap());
    let transport = std::sync::Arc::new(HttpsPeerTransport::new(host.identity().clone()));
    let inbound = std::sync::Arc::new(aionui_network::InboundService::new(repo.clone(), std::sync::Arc::new(support::FakeRunner::default()), host.clone()));
    let outbound = std::sync::Arc::new(aionui_network::OutboundService::new(repo.clone(), transport.clone()));
    let service = std::sync::Arc::new(aionui_network::NetworkService::new(repo, host, inbound, outbound, transport));
    service.start(None).await.unwrap();
    service.update_settings(OWNER, aionui_api_types::UpdateNetworkSettingsRequest {
        enabled: Some(true), listen_port: Some(port), display_name: None,
    }).await.unwrap();
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn lan_outbox_delivers_after_sender_process_restart() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    struct Sink(std::sync::Arc<dyn aionui_db::INetworkRepository>);
    #[async_trait::async_trait]
    impl aionui_network::LanTeamMessageSink for Sink {
        async fn deliver(&self, owner: &str, _: &str, fingerprint: &str, body: &aionui_api_types::PeerTeamMessage)
            -> Result<aionui_api_types::PeerTeamMessageResponse, NetworkError> {
            let row = aionui_db::models::MailboxMessageRow {
                id: uuid::Uuid::now_v7().to_string(), team_id: body.team_id.clone(), to_agent_id: "lead".into(),
                from_agent_id: "remote".into(), msg_type: "message".into(), content: body.content.clone(),
                summary: None, files: None, read: false, created_at: now_ms(),
            };
            match self.0.enqueue_lan_team_message(owner, fingerprint, &body.remote_team_id, &body.request_id, &row).await? {
                aionui_db::LanMessageEnqueue::Inserted => Ok(aionui_api_types::PeerTeamMessageResponse { duplicate: false }),
                aionui_db::LanMessageEnqueue::Duplicate => Ok(aionui_api_types::PeerTeamMessageResponse { duplicate: true }),
                aionui_db::LanMessageEnqueue::Conflict => Err(NetworkError::RequestConflict),
                aionui_db::LanMessageEnqueue::Unauthorized => Err(NetworkError::TeamNotFound),
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let db = aionui_db::init_database(&dir.path().join("host.sqlite")).await.unwrap();
    let repo: std::sync::Arc<dyn aionui_db::INetworkRepository> = std::sync::Arc::new(aionui_db::SqliteNetworkRepository::new(db.pool().clone()));
    let a = support::build_host("A", dir, db, repo).await;
    let b = start_host("B").await;
    pair(&a, &b).await;
    for (host, local, other, remote) in [(&a, "team-a", &b, "team-b"), (&b, "team-b", &a, "team-a")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(local).bind(OWNER).bind(local).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, local, true).await.unwrap();
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES (?, ?, ?, 'active')")
            .bind(local).bind(other.host.fingerprint().as_str()).bind(remote).execute(host._db.pool()).await.unwrap();
    }
    assert!(b.inbound.set_team_sink(std::sync::Arc::new(Sink(b.repo.clone()))).is_ok());
    b.set_listening(false).await;
    let id = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "restart delivery").await.unwrap();
    a.set_listening(false).await;
    let TestHost { service, inbound, repo, host, runner, port, _db, _dir } = a;
    drop((service, inbound, repo, host, runner, _db));
    let db = aionui_db::init_database(&_dir.path().join("host.sqlite")).await.unwrap();
    let spawn = || Child(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lan_outbox_restart_child", "--nocapture"])
        .env("AIONX_TEST_RESTART_DIR", _dir.path())
        .env("AIONX_TEST_RESTART_PORT", port.to_string())
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
    let child = spawn();
    eventually("first sender process listening", || async {
        tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok().map(|_| ())
    }).await;
    eventually("first sender process schedules retry", || async {
        let (state, next): (String, i64) = sqlx::query_as("SELECT state, next_attempt_at FROM lan_team_outbox WHERE id = ?")
            .bind(&id).fetch_one(db.pool()).await.unwrap();
        (state == "pending" && next > now_ms()).then_some(())
    }).await;
    drop(child);
    b.set_listening(true).await;
    let _child = spawn();
    eventually("outbox delivered after sender process restart", || async {
        let state: String = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id = ?").bind(&id).fetch_one(db.pool()).await.unwrap();
        (state == "delivered").then_some(())
    }).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE content = 'restart delivery'")
        .fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn stalled_invitation_does_not_block_other_team_messages() {
    struct Sink;
    #[async_trait::async_trait]
    impl aionui_network::LanTeamMessageSink for Sink {
        async fn deliver(&self, _: &str, _: &str, _: &str, _: &aionui_api_types::PeerTeamMessage)
            -> Result<aionui_api_types::PeerTeamMessageResponse, NetworkError> {
            Ok(aionui_api_types::PeerTeamMessageResponse { duplicate: false })
        }
    }
    let (a, b, coordinator) = (start_host("A").await, start_host("B").await, start_host("Coordinator").await);
    pair(&a, &b).await;
    for (host, local, other, remote) in [(&a, "team-a", &b, "team-b"), (&b, "team-b", &a, "team-a")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(local).bind(OWNER).bind(local).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, local, true).await.unwrap();
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES (?, ?, ?, 'active')")
            .bind(local).bind(other.host.fingerprint().as_str()).bind(remote).execute(host._db.pool()).await.unwrap();
    }
    assert!(b.inbound.set_team_sink(std::sync::Arc::new(Sink)).is_ok());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            tokio::spawn(async move { let _socket = socket; tokio::time::sleep(std::time::Duration::from_secs(10)).await; });
        }
    });
    a.repo.insert_peer(aionui_db::InsertPeerParams {
        fingerprint: coordinator.host.fingerprint().as_str(), display_name: "Coordinator", peer_url: Some(&url),
        state: "trusted", verification_code: "123456",
    }).await.unwrap();
    sqlx::query("INSERT INTO lan_team_poll_consents (coordinator_fingerprint, invitation_id, team_id, participants) VALUES (?, 'stalled-poll', 'team-a', '[]')")
        .bind(coordinator.host.fingerprint().as_str()).execute(a._db.pool()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        accepted_rx.recv().await.unwrap();
        accepted_rx.recv().await.unwrap();
    }).await.expect("poll reconciliation must reach the stalled coordinator");
    let id = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "while poll is stalled").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        loop {
            let state: String = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id = ?")
                .bind(&id).fetch_one(a._db.pool()).await.unwrap();
            if state == "delivered" { break; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.expect("a stalled poll must not block delivery to another peer");
    server.abort();
}

#[tokio::test]
async fn stalled_pending_peer_does_not_delay_an_approved_pairing() {
    let (a, b, stalled) = (start_host("A").await, start_host("B").await, start_host("Stalled").await);
    let pending = a.service.add_peer(OWNER, AddPeerRequest { url: b.url() }).await.unwrap();
    b.service.approve_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move { let _socket = socket; tokio::time::sleep(std::time::Duration::from_secs(10)).await; });
        }
    });
    a.repo.insert_peer(aionui_db::InsertPeerParams {
        fingerprint: stalled.host.fingerprint().as_str(), display_name: "Stalled", peer_url: Some(&url),
        state: "pending_outbound", verification_code: "123456",
    }).await.unwrap();
    let peers = tokio::time::timeout(std::time::Duration::from_secs(4), a.service.list_peers(OWNER))
        .await.expect("a stalled peer must not delay the approved pairing").unwrap();
    assert_eq!(peers.iter().find(|peer| peer.id == pending.id).unwrap().state, PeerState::Trusted);
    assert_eq!(peers.iter().find(|peer| peer.fingerprint == stalled.host.fingerprint().as_str()).unwrap().state, PeerState::PendingOutbound);
    server.abort();
}

#[tokio::test]
async fn roster_sync_projects_only_active_trusted_members() {
    struct Sink(std::sync::Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl aionui_network::LanTeamMessageSink for Sink {
        async fn sync_member(&self, _: &str, member: &aionui_db::ActiveLanTeamMember) -> Result<(), NetworkError> {
            self.0.lock().unwrap().push(member.remote_team_id.clone());
            Ok(())
        }
        async fn deliver(&self, _: &str, _: &str, _: &str, _: &aionui_api_types::PeerTeamMessage)
            -> Result<aionui_api_types::PeerTeamMessageResponse, NetworkError> { unreachable!() }
    }
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-b', ?, 'B', 1, 1)")
        .bind(OWNER).execute(b._db.pool()).await.unwrap();
    b.service.set_team_shared(OWNER, "team-b", true).await.unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    let sink = std::sync::Arc::new(Sink(std::sync::Mutex::new(Vec::new())));
    assert!(b.inbound.set_team_sink(sink.clone()).is_ok());
    b.inbound.sync_team_members().await.unwrap();
    assert!(sink.0.lock().unwrap().iter().any(|id| id == "team-a"));
    b.service.revoke_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    sink.0.lock().unwrap().clear();
    b.inbound.sync_team_members().await.unwrap();
    assert!(sink.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn team_message_endpoint_authenticates_membership_and_deduplicates_over_mtls() {
    struct Sink(std::sync::Arc<dyn aionui_db::INetworkRepository>);
    #[async_trait::async_trait]
    impl aionui_network::LanTeamMessageSink for Sink {
        async fn deliver(&self, owner: &str, _peer: &str, fingerprint: &str, body: &aionui_api_types::PeerTeamMessage)
            -> Result<aionui_api_types::PeerTeamMessageResponse, NetworkError> {
            let message = aionui_db::models::MailboxMessageRow {
                id: uuid::Uuid::now_v7().to_string(), team_id: body.team_id.clone(), to_agent_id: "lead".into(),
                from_agent_id: "remote".into(), msg_type: "message".into(), content: body.content.clone(),
                summary: None, files: None, read: false, created_at: now_ms(),
            };
            match self.0.enqueue_lan_team_message(owner, fingerprint, &body.remote_team_id, &body.request_id, &message).await? {
                aionui_db::LanMessageEnqueue::Inserted => Ok(aionui_api_types::PeerTeamMessageResponse { duplicate: false }),
                aionui_db::LanMessageEnqueue::Duplicate => Ok(aionui_api_types::PeerTeamMessageResponse { duplicate: true }),
                aionui_db::LanMessageEnqueue::Conflict => Err(NetworkError::RequestConflict),
                aionui_db::LanMessageEnqueue::Unauthorized => Err(NetworkError::TeamNotFound),
            }
        }
    }
    let (a, b, stranger) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&stranger, &b).await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-b', ?, 'B', 1, 1)")
        .bind(OWNER).execute(b._db.pool()).await.unwrap();
    b.service.set_team_shared(OWNER, "team-b", true).await.unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    assert!(b.inbound.set_team_sink(std::sync::Arc::new(Sink(b.repo.clone()))).is_ok());
    let transport = HttpsPeerTransport::new(a.host.identity().clone());
    let outsider = HttpsPeerTransport::new(stranger.host.identity().clone());
    let mut message = aionui_api_types::PeerTeamMessage { request_id: "message-1".into(), team_id: "team-b".into(), remote_team_id: "team-a".into(), content: "hello".into() };
    assert!(matches!(outsider.send_team_message(&b.url(), b.host.fingerprint(), &message).await, Err(NetworkError::PeerRejected { code, .. }) if code == "TEAM_NOT_FOUND"));
    assert!(!transport.send_team_message(&b.url(), b.host.fingerprint(), &message).await.unwrap().duplicate);
    assert!(transport.send_team_message(&b.url(), b.host.fingerprint(), &message).await.unwrap().duplicate);
    message.content = "changed".into();
    assert!(matches!(transport.send_team_message(&b.url(), b.host.fingerprint(), &message).await, Err(NetworkError::RequestConflict)));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE team_id = 'team-b'").fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(count, 1);
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-a', ?, 'A', 1, 1)")
        .bind(OWNER).execute(a._db.pool()).await.unwrap();
    a.service.set_team_shared(OWNER, "team-a", true).await.unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-a', ?, 'team-b', 'active')")
        .bind(b.host.fingerprint().as_str()).execute(a._db.pool()).await.unwrap();
    b.set_listening(false).await;
    let queued = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "queued offline").await.unwrap();
    let second = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "queued second").await.unwrap();
    let third = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "queued third").await.unwrap();
    assert!(matches!(a.service.lan_team_delivery_statuses("other", "team-a").await, Err(NetworkError::OwnerOnly)));
    assert!(a.service.lan_team_delivery_statuses(OWNER, "other-team").await.unwrap().is_empty());
    assert!(a.service.lan_team_delivery_statuses(OWNER, "team-a").await.unwrap().iter().any(|item| item.message_id == queued && item.state == "pending"));
    let state: String = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id = ?").bind(&queued).fetch_one(a._db.pool()).await.unwrap();
    assert_eq!(state, "pending");
    b.set_listening(true).await;
    eventually("offline team message delivered after reconnect", || async {
        let states: Vec<String> = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id IN (?, ?, ?) ORDER BY rowid")
            .bind(&queued).bind(&second).bind(&third).fetch_all(a._db.pool()).await.unwrap();
        (states == vec!["delivered"; 3]).then_some(())
    }).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE team_id = 'team-b' AND content = 'queued offline'")
        .fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(count, 1);
    let received: Vec<String> = sqlx::query_scalar("SELECT content FROM mailbox WHERE team_id = 'team-b' AND content IN ('queued offline', 'queued second', 'queued third') ORDER BY rowid")
        .fetch_all(b._db.pool()).await.unwrap();
    assert_eq!(received, vec!["queued offline", "queued second", "queued third"]);
    b.service.set_team_shared(OWNER, "team-b", false).await.unwrap();
    let paused = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "sharing paused").await.unwrap();
    eventually("unshared conversation defers the message", || async {
        let (state, next): (String, i64) = sqlx::query_as("SELECT state, next_attempt_at FROM lan_team_outbox WHERE id = ?")
            .bind(&paused).fetch_one(a._db.pool()).await.unwrap();
        (state == "pending" && next > now_ms()).then_some(())
    }).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE team_id = 'team-b' AND content = 'sharing paused'")
        .fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(count, 0);
    b.service.set_team_shared(OWNER, "team-b", true).await.unwrap();
    eventually("message delivered after sharing resumes", || async {
        let state: String = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id = ?")
            .bind(&paused).fetch_one(a._db.pool()).await.unwrap();
        (state == "delivered").then_some(())
    }).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox WHERE team_id = 'team-b' AND content = 'sharing paused'")
        .fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(count, 1);
    b.set_listening(false).await;
    let revoked = a.service.send_lan_team_message(OWNER, "team-a", &a.peer_id_of(&b).await, "team-b", "do not send").await.unwrap();
    a.service.revoke_peer(OWNER, &a.peer_id_of(&b).await).await.unwrap();
    eventually("revoked team message stops retrying", || async {
        let state: String = sqlx::query_scalar("SELECT state FROM lan_team_outbox WHERE id = ?").bind(&revoked).fetch_one(a._db.pool()).await.unwrap();
        (state == "revoked").then_some(())
    }).await;
    b.set_listening(true).await;
    b.service.revoke_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    assert!(matches!(transport.send_team_message(&b.url(), b.host.fingerprint(), &message).await, Err(NetworkError::PeerRevoked)));
}

#[tokio::test]
async fn pinned_pairing_rejects_address_with_a_different_identity() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    let request = aionui_api_types::AddPinnedPeerRequest { url: b.url(), fingerprint: c.host.fingerprint().to_string() };
    assert!(matches!(a.service.add_pinned_peer(OWNER, request).await, Err(NetworkError::FingerprintMismatch)));
    assert!(a.repo.list_peers().await.unwrap().is_empty());
    assert!(b.repo.list_peers().await.unwrap().is_empty());
    let request = aionui_api_types::AddPinnedPeerRequest { url: b.url(), fingerprint: b.host.fingerprint().to_string() };
    assert_eq!(a.service.add_pinned_peer(OWNER, request).await.unwrap().state, PeerState::PendingOutbound);
    assert_eq!(b.repo.list_peers().await.unwrap()[0].state, "pending_inbound");
}

#[tokio::test]
async fn competing_team_invitations_can_be_resolved_without_split_rosters() {
    let (a, b, c, d) = (start_host("A").await, start_host("B").await, start_host("C").await, start_host("D").await);
    pair(&a, &b).await;
    pair(&a, &c).await;
    pair(&b, &d).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c"), (&d, "team-d")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    for (host, team, peer, remote) in [(&a, "team-a", &b, "team-b"), (&b, "team-b", &a, "team-a")] {
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES (?, ?, ?, 'active')")
            .bind(team).bind(peer.host.fingerprint().as_str()).bind(remote).execute(host._db.pool()).await.unwrap();
    }
    for (host, peer) in [(&a, &b), (&a, &c), (&b, &a), (&b, &d), (&d, &b)] {
        host.service.observe_known_peer(OWNER, AddPeerRequest { url: peer.url() }).await.unwrap();
    }
    let first = a.service.create_team_invitation(OWNER, "team-a", &a.peer_id_of(&c).await).await.unwrap();
    let second = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&d).await).await.unwrap();
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), d.host.fingerprint().to_string()];
    let approve = aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: second.id.clone(), approve: true, team_id: Some("team-a".into()), participants: participants.clone(),
    };
    assert!(matches!(a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await, approve.clone()).await, Err(NetworkError::InvalidRequest(_))));
    let reject = aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: first.id.clone(), approve: false, team_id: None, participants: vec![],
    };
    assert!(b.service.vote_remote_team_invitation(OWNER, &b.peer_id_of(&a).await, reject).await.unwrap().recorded);
    assert!(a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await, approve).await.unwrap().recorded);
    assert!(d.service.vote_remote_team_invitation(OWNER, &d.peer_id_of(&b).await, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: second.id, approve: true, team_id: Some("team-d".into()), participants,
    }).await.unwrap().recorded);
    eventually("winning poll synchronizes A, B and D", || async {
        for (host, team, others) in [
            (&a, "team-a", vec![(&b, "team-b"), (&d, "team-d")]),
            (&b, "team-b", vec![(&a, "team-a"), (&d, "team-d")]),
            (&d, "team-d", vec![(&a, "team-a"), (&b, "team-b")]),
        ] {
            for (peer, remote) in others {
                let found: Option<(String, String)> = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = ? AND fingerprint = ?")
                    .bind(team).bind(peer.host.fingerprint().as_str()).fetch_optional(host._db.pool()).await.unwrap();
                if found != Some((remote.to_owned(), "active".to_owned())) { return None; }
            }
        }
        Some(())
    }).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&d, "team-d")] {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_team_members WHERE team_id = ? AND fingerprint = ? AND state = 'active'")
            .bind(team).bind(c.host.fingerprint().as_str()).fetch_one(host._db.pool()).await.unwrap();
        assert_eq!(count, 0);
    }
}

#[tokio::test]
async fn coordinator_recovers_pending_poll_after_process_restart() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let dir = tempfile::tempdir().unwrap();
    let db = aionui_db::init_database(&dir.path().join("host.sqlite")).await.unwrap();
    let repo: std::sync::Arc<dyn aionui_db::INetworkRepository> = std::sync::Arc::new(aionui_db::SqliteNetworkRepository::new(db.pool().clone()));
    let b = support::build_host("B", dir, db, repo).await;
    let (a, c) = (start_host("A").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&c, &b).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    for host in [&a, &c] {
        b.service.observe_known_peer(OWNER, AddPeerRequest { url: host.url() }).await.unwrap();
    }
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.unwrap();
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()];
    a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()), participants: participants.clone() }).await.unwrap();
    let b_fingerprint = b.host.fingerprint().to_string();
    let b_on_c = c.peer_id_of(&b).await;
    b.set_listening(false).await;
    let TestHost { service, inbound, repo, host, runner, port, _db, _dir } = b;
    drop((service, inbound, repo, host, runner, _db));
    let db = aionui_db::init_database(&_dir.path().join("host.sqlite")).await.unwrap();
    let _child = Child(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lan_outbox_restart_child", "--nocapture"])
        .env("AIONX_TEST_RESTART_DIR", _dir.path())
        .env("AIONX_TEST_RESTART_PORT", port.to_string())
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
    eventually("restarted coordinator serves pending invitation", || async {
        c.service.remote_team_invitations(OWNER, &b_on_c).await.ok()
            .filter(|polls| polls.iter().any(|poll| poll.id == invitation.id)).map(|_| ())
    }).await;
    c.service.vote_remote_team_invitation(OWNER, &b_on_c,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-c".into()), participants }).await.unwrap();
    eventually("restarted coordinator completes all rosters", || async {
        for (pool, local, members) in [
            (a._db.pool(), "team-a", vec![(b_fingerprint.as_str(), "team-b"), (c.host.fingerprint().as_str(), "team-c")]),
            (db.pool(), "team-b", vec![(a.host.fingerprint().as_str(), "team-a"), (c.host.fingerprint().as_str(), "team-c")]),
            (c._db.pool(), "team-c", vec![(a.host.fingerprint().as_str(), "team-a"), (b_fingerprint.as_str(), "team-b")]),
        ] {
            for (fingerprint, remote) in members {
                let member: Option<(String, String)> = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = ? AND fingerprint = ?")
                    .bind(local).bind(fingerprint).fetch_optional(pool).await.unwrap();
                if member != Some((remote.into(), "active".into())) { return None; }
            }
        }
        Some(())
    }).await;
}

#[tokio::test]
async fn approved_participant_recovers_poll_after_process_restart() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let dir = tempfile::tempdir().unwrap();
    let db = aionui_db::init_database(&dir.path().join("host.sqlite")).await.unwrap();
    let repo: std::sync::Arc<dyn aionui_db::INetworkRepository> = std::sync::Arc::new(aionui_db::SqliteNetworkRepository::new(db.pool().clone()));
    let a = support::build_host("A", dir, db, repo).await;
    let (b, c) = (start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&c, &b).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    for host in [&a, &c] {
        b.service.observe_known_peer(OWNER, AddPeerRequest { url: host.url() }).await.unwrap();
    }
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.unwrap();
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()];
    a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()), participants: participants.clone() }).await.unwrap();
    let a_fingerprint = a.host.fingerprint().to_string();
    a.set_listening(false).await;
    let TestHost { service, inbound, repo, host, runner, port, _db, _dir } = a;
    drop((service, inbound, repo, host, runner, _db));
    c.service.vote_remote_team_invitation(OWNER, &c.peer_id_of(&b).await,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-c".into()), participants }).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM lan_team_invitations WHERE id = ?")
        .bind(&invitation.id).fetch_one(b._db.pool()).await.unwrap();
    assert_ne!(state, "completed");
    let db = aionui_db::init_database(&_dir.path().join("host.sqlite")).await.unwrap();
    let _child = Child(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lan_outbox_restart_child", "--nocapture"])
        .env("AIONX_TEST_RESTART_DIR", _dir.path())
        .env("AIONX_TEST_RESTART_PORT", port.to_string())
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
    eventually("restarted participant synchronizes all rosters", || async {
        for (pool, local, members) in [
            (db.pool(), "team-a", vec![(b.host.fingerprint().as_str(), "team-b"), (c.host.fingerprint().as_str(), "team-c")]),
            (b._db.pool(), "team-b", vec![(a_fingerprint.as_str(), "team-a"), (c.host.fingerprint().as_str(), "team-c")]),
            (c._db.pool(), "team-c", vec![(a_fingerprint.as_str(), "team-a"), (b.host.fingerprint().as_str(), "team-b")]),
        ] {
            for (fingerprint, remote) in members {
                let member: Option<(String, String)> = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = ? AND fingerprint = ?")
                    .bind(local).bind(fingerprint).fetch_optional(pool).await.unwrap();
                if member != Some((remote.into(), "active".into())) { return None; }
            }
        }
        Some(())
    }).await;
}

#[tokio::test]
async fn approved_poll_exposes_known_pairing_addresses_only_after_all_votes() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&c, &b).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    for host in [&a, &c] {
        b.service.observe_known_peer(OWNER, AddPeerRequest { url: host.url() }).await.unwrap();
    }
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.unwrap();
    let before = a.service.remote_team_invitations(OWNER, &a.peer_id_of(&b).await).await.unwrap();
    assert!(!before[0].ready_for_pairing);
    assert!(!before[0].pairing_verified);
    assert!(before[0].participants.iter().all(|participant| participant.peer_url.is_none()));
    assert!(before[0].participants.iter().all(|participant| participant.team_id.is_none()));
    let transport = HttpsPeerTransport::new(a.host.identity().clone());
    let attestation = aionui_api_types::PeerPairAttestationRequest {
        invitation_id: invitation.id.clone(),
        participants: vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()],
    };
    assert!(!transport.attest_team_pairs(&b.url(), b.host.fingerprint(), &attestation).await.unwrap().recorded);
    assert!(matches!(a.service.reconcile_team_invitation(OWNER, &a.peer_id_of(&b).await, &invitation.id).await, Err(NetworkError::RequestNotFound)));
    for (host, team) in [(&a, "team-a"), (&c, "team-c")] {
        host.service.vote_remote_team_invitation(OWNER, &host.peer_id_of(&b).await,
            aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some(team.into()), participants: vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()] })
            .await.unwrap();
        if team == "team-a" {
            let partial = a.service.remote_team_invitations(OWNER, &a.peer_id_of(&b).await).await.unwrap();
            assert!(!partial[0].ready_for_pairing);
            assert!(partial[0].participants.iter().all(|participant| participant.team_id.is_none()));
        }
    }
    let after = a.service.remote_team_invitations(OWNER, &a.peer_id_of(&b).await).await.unwrap();
    assert!(after[0].ready_for_pairing);
    let local = b.service.pending_local_team_invitation(OWNER, "team-b").await.unwrap().unwrap();
    assert_eq!(local.participants.len(), 3);
    assert!(local.participants.iter().all(|participant| participant.decision == "approved" && participant.display_name.is_some()));
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        assert_eq!(after[0].participants.iter().find(|participant| participant.fingerprint == host.host.fingerprint().as_str()).unwrap().team_id.as_deref(), Some(team));
    }
    let wrong_attestation = aionui_api_types::PeerPairAttestationRequest {
        participants: vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string()],
        ..attestation
    };
    assert!(!transport.attest_team_pairs(&b.url(), b.host.fingerprint(), &wrong_attestation).await.unwrap().recorded);
    assert!(after[0].participants.iter().any(|participant| participant.fingerprint == c.host.fingerprint().as_str() && participant.peer_url.as_deref() == Some(c.url().as_str())));
    let consent = a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().unwrap();
    sqlx::query("UPDATE lan_team_poll_consents SET participants = '[]' WHERE invitation_id = ?")
        .bind(&invitation.id).execute(a._db.pool()).await.unwrap();
    assert!(matches!(a.service.reconcile_team_invitation(OWNER, &a.peer_id_of(&b).await, &invitation.id).await, Err(NetworkError::RequestConflict)));
    sqlx::query("UPDATE lan_team_poll_consents SET participants = ? WHERE invitation_id = ?")
        .bind(&consent.1).bind(&invitation.id).execute(a._db.pool()).await.unwrap();
    eventually("automatic pair after approval", || async {
        let on_a = a.repo.find_peer_by_fingerprint(c.host.fingerprint().as_str()).await.unwrap();
        let on_c = c.repo.find_peer_by_fingerprint(a.host.fingerprint().as_str()).await.unwrap();
        (on_a.as_ref().is_some_and(|p| p.state == "trusted") && on_c.as_ref().is_some_and(|p| p.state == "trusted")).then_some(())
    }).await;
    let c_on_a = a.repo.find_peer_by_fingerprint(c.host.fingerprint().as_str()).await.unwrap().unwrap();
    let a_on_c = c.repo.find_peer_by_fingerprint(a.host.fingerprint().as_str()).await.unwrap().unwrap();
    assert_eq!(c_on_a.state, "trusted");
    assert_eq!(a_on_c.state, "trusted");
    eventually("all hosts synchronize the approved conversation roster", || async {
        for (host, local, others) in [
            (&a, "team-a", vec![(&b, "team-b"), (&c, "team-c")]),
            (&b, "team-b", vec![(&a, "team-a"), (&c, "team-c")]),
            (&c, "team-c", vec![(&a, "team-a"), (&b, "team-b")]),
        ] {
            for (other, team) in others {
                let found: Option<(String, String)> = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = ? AND fingerprint = ?")
                    .bind(local).bind(other.host.fingerprint().as_str()).fetch_optional(host._db.pool()).await.unwrap();
                if found != Some((team.to_owned(), "active".to_owned())) { return None; }
            }
        }
        Some(())
    }).await;
    let state: String = sqlx::query_scalar("SELECT state FROM lan_team_invitations WHERE id = ?")
        .bind(&invitation.id).fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(state, "completed");
    assert!(!b.repo.team_pair_attestations_complete(OWNER, &invitation.id, i64::MAX).await.unwrap());
    assert!(!a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: false, team_id: None, participants: vec![] })
        .await.unwrap().recorded);

    let d = start_host("D").await;
    pair(&b, &d).await;
    d.service.observe_known_peer(OWNER, AddPeerRequest { url: b.url() }).await.unwrap();
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-d', ?, 'D', 1, 1)")
        .bind(OWNER).execute(d._db.pool()).await.unwrap();
    d.service.set_team_shared(OWNER, "team-d", true).await.unwrap();
    let fourth = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&d).await).await.unwrap();
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string(), d.host.fingerprint().to_string()];
    for (host, team) in [(&a, "team-a"), (&c, "team-c")] {
        host.service.vote_remote_team_invitation(OWNER, &host.peer_id_of(&b).await,
            aionui_api_types::PeerInvitationVoteRequest { invitation_id: fourth.id.clone(), approve: true, team_id: Some(team.into()), participants: participants.clone() })
            .await.unwrap();
    }
    assert!(!a.service.remote_team_invitations(OWNER, &a.peer_id_of(&b).await).await.unwrap()[0].ready_for_pairing);
    assert!(a.repo.find_peer_by_fingerprint(d.host.fingerprint().as_str()).await.unwrap().is_none());
    assert!(c.repo.find_peer_by_fingerprint(d.host.fingerprint().as_str()).await.unwrap().is_none());
    d.service.vote_remote_team_invitation(OWNER, &d.peer_id_of(&b).await,
        aionui_api_types::PeerInvitationVoteRequest { invitation_id: fourth.id.clone(), approve: true, team_id: Some("team-d".into()), participants })
        .await.unwrap();
    eventually("four hosts pair and synchronize the expanded roster", || async {
        for (host, local) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c"), (&d, "team-d")] {
            for (other, remote) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c"), (&d, "team-d")] {
                if local == remote { continue; }
                let peer = host.repo.find_peer_by_fingerprint(other.host.fingerprint().as_str()).await.unwrap();
                if peer.is_none_or(|peer| peer.state != "trusted") { return None; }
                let member: Option<(String, String)> = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = ? AND fingerprint = ?")
                    .bind(local).bind(other.host.fingerprint().as_str()).fetch_optional(host._db.pool()).await.unwrap();
                if member != Some((remote.into(), "active".into())) { return None; }
            }
        }
        Some(())
    }).await;
    b.service.revoke_peer(OWNER, &b.peer_id_of(&c).await).await.unwrap();
    assert!(a.service.remote_team_invitations(OWNER, &a.peer_id_of(&b).await).await.unwrap().is_empty());
}

#[tokio::test]
async fn declined_poll_clears_prior_consent_without_pairing_remaining_hosts() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&b, &a).await;
    pair(&b, &c).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    for host in [&a, &c] {
        host.service.observe_known_peer(OWNER, AddPeerRequest { url: b.url() }).await.unwrap();
    }
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.unwrap();
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()];
    a.service.vote_remote_team_invitation(OWNER, &a.peer_id_of(&b).await, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()), participants,
    }).await.unwrap();
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_some());
    b.set_listening(false).await;
    assert!(a.service.reconcile_team_invitation(OWNER, &a.peer_id_of(&b).await, &invitation.id).await.is_err());
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_some());
    b.set_listening(true).await;
    c.service.vote_remote_team_invitation(OWNER, &c.peer_id_of(&b).await, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: false, team_id: None, participants: vec![],
    }).await.unwrap();
    eventually("approved participant drops rejected poll consent", || async {
        a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_none().then_some(())
    }).await;
    assert!(a.repo.find_peer_by_fingerprint(c.host.fingerprint().as_str()).await.unwrap().is_none());
    assert!(c.repo.find_peer_by_fingerprint(a.host.fingerprint().as_str()).await.unwrap().is_none());
    let rejected = b.service.pending_local_team_invitation(OWNER, "team-b").await.unwrap().unwrap();
    assert_eq!(rejected.state, "rejected");
    assert!(rejected.participants.iter().any(|participant| participant.fingerprint == c.host.fingerprint().as_str() && participant.decision == "rejected"));
    assert!(b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.is_ok());
}

#[tokio::test]
async fn participant_can_withdraw_approval_before_poll_completes() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&c, &b).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b"), (&c, "team-c")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', ?, 'team-a', 'active')")
        .bind(a.host.fingerprint().as_str()).execute(b._db.pool()).await.unwrap();
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&c).await).await.unwrap();
    let coordinator = a.peer_id_of(&b).await;
    let participants = vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string(), c.host.fingerprint().to_string()];
    assert!(a.service.vote_remote_team_invitation(OWNER, &coordinator, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()), participants,
    }).await.unwrap().recorded);
    b.set_listening(false).await;
    assert!(a.service.vote_remote_team_invitation(OWNER, &coordinator, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: false, team_id: None, participants: vec![],
    }).await.is_err());
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_some());
    b.set_listening(true).await;
    assert!(a.service.vote_remote_team_invitation(OWNER, &coordinator, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: false, team_id: None, participants: vec![],
    }).await.unwrap().recorded);
    assert!(a.service.vote_remote_team_invitation(OWNER, &coordinator, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: false, team_id: None, participants: vec![],
    }).await.unwrap().recorded);
    let poll = b.service.pending_local_team_invitation(OWNER, "team-b").await.unwrap().unwrap();
    assert_eq!(poll.state, "rejected");
    assert!(poll.participants.iter().any(|vote| vote.fingerprint == a.host.fingerprint().as_str() && vote.decision == "rejected"));
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_none());
    assert!(a.repo.find_peer_by_fingerprint(c.host.fingerprint().as_str()).await.unwrap().is_none());
    assert!(!c.service.vote_remote_team_invitation(OWNER, &c.peer_id_of(&b).await, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id, approve: false, team_id: None, participants: vec![],
    }).await.unwrap().recorded);
}

#[tokio::test]
async fn discovery_recovers_known_peer_address_without_pairing_unknown_hosts() {
    let (a, b, stranger) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    let a_on_b = b.peer_id_of(&a).await;
    assert!(b.repo.find_peer(&a_on_b).await.unwrap().unwrap().peer_url.is_none());
    assert!(matches!(b.service.observe_known_peer("other", AddPeerRequest { url: a.url() }).await, Err(NetworkError::OwnerOnly)));
    let unknown = b.service.observe_known_peer(OWNER, AddPeerRequest { url: stranger.url() }).await.unwrap().unwrap();
    assert_eq!(unknown.fingerprint, stranger.host.fingerprint().as_str());
    assert_eq!(unknown.state, None);
    assert!(b.repo.find_peer_by_fingerprint(stranger.host.fingerprint().as_str()).await.unwrap().is_none());
    assert_eq!(b.service.observe_known_peer(OWNER, AddPeerRequest { url: a.url() }).await.unwrap().unwrap().state, Some(PeerState::Trusted));
    assert_eq!(b.repo.find_peer(&a_on_b).await.unwrap().unwrap().peer_url.as_deref(), Some(a.url().as_str()));
    b.service.revoke_peer(OWNER, &a_on_b).await.unwrap();
    assert_eq!(b.service.observe_known_peer(OWNER, AddPeerRequest { url: a.url() }).await.unwrap().unwrap().state, Some(PeerState::Revoked));
}

#[tokio::test]
async fn revocation_preserves_membership_history_and_cancels_affected_polls_on_both_hosts() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&a, &c).await;
    pair(&b, &c).await;
    for (host, member) in [(&a, &b), (&b, &a)] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', ?, 'Team', 1, 1)")
            .bind(OWNER).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, "team", true).await.unwrap();
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', ?, 'remote', 'active')")
            .bind(member.host.fingerprint().as_str()).execute(host._db.pool()).await.unwrap();
        host.service.create_team_invitation(OWNER, "team", &host.peer_id_of(&c).await).await.unwrap();
    }
    b.service.revoke_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    a.service.list_peers(OWNER).await.unwrap();
    for (host, member) in [(&a, &b), (&b, &a)] {
        let membership: (String, String) = sqlx::query_as("SELECT remote_team_id, state FROM lan_team_members WHERE team_id = 'team' AND fingerprint = ?")
            .bind(member.host.fingerprint().as_str()).fetch_one(host._db.pool()).await.unwrap();
        assert_eq!(membership, ("remote".into(), "revoked".into()));
        let state: String = sqlx::query_scalar("SELECT state FROM lan_team_invitations WHERE team_id = 'team'")
            .fetch_one(host._db.pool()).await.unwrap();
        assert_eq!(state, "cancelled");
    }
}

#[tokio::test]
async fn invitation_vote_uses_authenticated_peer_identity() {
    let (a, b, c) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    pair(&c, &b).await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', ?, 'Team', 1, 1)")
        .bind(OWNER)
        .execute(b._db.pool())
        .await
        .unwrap();
    b.service.set_team_shared(OWNER, "team", true).await.unwrap();
    let candidate = b.peer_id_of(&a).await;
    assert!(matches!(b.service.create_team_invitation("other", "team", &candidate).await, Err(NetworkError::OwnerOnly)));
    let invitation = b.service.create_team_invitation(OWNER, "team", &candidate).await.unwrap();
    assert!(matches!(b.service.cancel_team_invitation("other", "team", &invitation.id).await, Err(NetworkError::OwnerOnly)));
    assert!(matches!(b.service.cancel_team_invitation(OWNER, "wrong-team", &invitation.id).await, Err(NetworkError::RequestNotFound)));
    assert_eq!(b.service.pending_local_team_invitation(OWNER, "team").await.unwrap().unwrap().candidate_fingerprint, a.host.fingerprint().as_str());
    assert!(b.service.pending_local_team_invitation(OWNER, "other-team").await.unwrap().is_none());
    assert!(matches!(b.service.pending_local_team_invitation("other", "team").await, Err(NetworkError::OwnerOnly)));
    assert!(matches!(b.service.create_team_invitation(OWNER, "team", &candidate).await, Err(NetworkError::RequestConflict)));
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-a', ?, 'A', 1, 1)")
        .bind(OWNER).execute(a._db.pool()).await.unwrap();
    let request = aionui_api_types::PeerInvitationVoteRequest { invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()), participants: vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string()] };
    let a_transport = HttpsPeerTransport::new(a.host.identity().clone());
    let c_transport = HttpsPeerTransport::new(c.host.identity().clone());
    let b_on_a = a.peer_id_of(&b).await;
    assert!(matches!(a.service.remote_team_invitations("other", &b_on_a).await, Err(NetworkError::OwnerOnly)));
    assert!(matches!(a.service.vote_remote_team_invitation("other", &b_on_a, request.clone()).await, Err(NetworkError::OwnerOnly)));
    assert!(matches!(a.service.vote_remote_team_invitation(OWNER, &b_on_a, request.clone()).await, Err(NetworkError::TeamNotFound)));
    a.service.set_team_shared(OWNER, "team-a", true).await.unwrap();
    let altered = aionui_api_types::PeerInvitationVoteRequest { participants: vec![a.host.fingerprint().to_string()], ..request.clone() };
    assert!(matches!(a.service.vote_remote_team_invitation(OWNER, &b_on_a, altered).await, Err(NetworkError::InvalidRequest(_))));
    assert_eq!(a.service.remote_team_invitations(OWNER, &b_on_a).await.unwrap().len(), 1);
    assert!(c_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await.unwrap().is_empty());
    let invitations = a_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await.unwrap();
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0].team_name, "Team");
    assert_eq!(invitations[0].candidate_fingerprint, a.host.fingerprint().as_str());
    assert_eq!(invitations[0].candidate_name.as_deref(), Some("A"));
    assert_eq!(invitations[0].decision, "pending");
    assert_eq!(invitations[0].participants.len(), 2);
    assert!(invitations[0].participants.iter().any(|v| v.fingerprint == b.host.fingerprint().as_str() && v.display_name.as_deref() == Some("B") && v.decision == "approved"));
    assert!(invitations[0].participants.iter().any(|v| v.fingerprint == a.host.fingerprint().as_str() && v.display_name.as_deref() == Some("A") && v.decision == "pending"));
    assert!(!c_transport.vote_invitation(&b.url(), b.host.fingerprint(), &request).await.unwrap().recorded);
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-a', ?, 'team-c', 'active')")
        .bind(c.host.fingerprint().as_str()).execute(a._db.pool()).await.unwrap();
    assert!(matches!(a.service.vote_remote_team_invitation(OWNER, &b_on_a, request.clone()).await, Err(NetworkError::InvalidRequest(_))));
    assert_eq!(a_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await.unwrap()[0].decision, "pending");
    sqlx::query("DELETE FROM lan_team_members WHERE team_id = 'team-a' AND fingerprint = ?")
        .bind(c.host.fingerprint().as_str()).execute(a._db.pool()).await.unwrap();
    assert!(a.service.vote_remote_team_invitation(OWNER, &b_on_a, request.clone()).await.unwrap().recorded);
    let consent = a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().unwrap();
    assert_eq!(consent.0, "team-a");
    let participants: Vec<String> = serde_json::from_str(&consent.1).unwrap();
    assert_eq!(participants.len(), 2);
    assert!(participants.contains(&b.host.fingerprint().to_string()));
    assert_eq!(a_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await.unwrap()[0].decision, "approved");
    assert!(a_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await.unwrap()[0].participants.iter().any(|v| v.fingerprint == a.host.fingerprint().as_str() && v.decision == "approved"));
    assert!(!a_transport.vote_invitation(&b.url(), b.host.fingerprint(), &request).await.unwrap().recorded);
    let votes = b.repo.team_invitation_votes(OWNER, &invitation.id).await.unwrap();
    assert!(votes.contains(&(a.host.fingerprint().to_string(), "approved".into())));
    assert!(votes.contains(&(b.host.fingerprint().to_string(), "approved".into())));
    assert!(matches!(b.service.vote_local_team_invitation("other", request.clone()).await, Err(NetworkError::OwnerOnly)));
    assert!(matches!(b.service.vote_local_team_invitation(OWNER, request.clone()).await, Err(NetworkError::InvalidRequest(_))));
    let local_request = aionui_api_types::PeerInvitationVoteRequest { team_id: Some("team".into()), ..request.clone() };
    assert!(!b.service.vote_local_team_invitation(OWNER, local_request).await.unwrap().recorded);
    let stored: Option<String> = sqlx::query_scalar("SELECT remote_team_id FROM lan_team_invitation_votes WHERE invitation_id = ? AND fingerprint = ?")
        .bind(&invitation.id).bind(a.host.fingerprint().as_str()).fetch_one(b._db.pool()).await.unwrap();
    assert_eq!(stored.as_deref(), Some("team-a"));
    b.service.revoke_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    assert!(matches!(a_transport.vote_invitation(&b.url(), b.host.fingerprint(), &request).await, Err(NetworkError::PeerRevoked)));
    assert!(matches!(a_transport.list_team_invitations(&b.url(), b.host.fingerprint()).await, Err(NetworkError::PeerRevoked)));
    a.service.list_peers(OWNER).await.unwrap();
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_none());
}

#[tokio::test]
async fn owner_cancels_pending_team_invitation_and_participant_clears_consent() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    for (host, team) in [(&a, "team-a"), (&b, "team-b")] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(team).bind(OWNER).bind(team).execute(host._db.pool()).await.unwrap();
        host.service.set_team_shared(OWNER, team, true).await.unwrap();
    }
    let invitation = b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&a).await).await.unwrap();
    let coordinator = a.peer_id_of(&b).await;
    a.service.vote_remote_team_invitation(OWNER, &coordinator, aionui_api_types::PeerInvitationVoteRequest {
        invitation_id: invitation.id.clone(), approve: true, team_id: Some("team-a".into()),
        participants: vec![a.host.fingerprint().to_string(), b.host.fingerprint().to_string()],
    }).await.unwrap();
    b.service.cancel_team_invitation(OWNER, "team-b", &invitation.id).await.unwrap();
    assert!(matches!(b.service.cancel_team_invitation(OWNER, "team-b", &invitation.id).await, Err(NetworkError::RequestNotFound)));
    assert_eq!(b.service.pending_local_team_invitation(OWNER, "team-b").await.unwrap().unwrap().state, "cancelled");
    a.service.reconcile_team_invitation(OWNER, &coordinator, &invitation.id).await.unwrap();
    assert!(a.repo.team_poll_consent(OWNER, b.host.fingerprint().as_str(), &invitation.id).await.unwrap().is_none());
    assert!(b.service.create_team_invitation(OWNER, "team-b", &b.peer_id_of(&a).await).await.is_ok());
}

#[tokio::test]
async fn trusted_peer_sees_only_enabled_conversations_and_loses_access_on_revoke() {
    let (a, b, stranger) = (start_host("A").await, start_host("B").await, start_host("C").await);
    for (id, owner, name) in [
        ("team-on", OWNER, "Shared team"),
        ("team-off", OWNER, "Private team"),
        ("other", "other", "Other user's team"),
    ] {
        sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
            .bind(id)
            .bind(owner)
            .bind(name)
            .execute(b._db.pool())
            .await
            .unwrap();
    }
    assert!(matches!(
        b.inbound.list_teams(stranger.host.fingerprint()).await,
        Err(NetworkError::PeerUntrusted)
    ));
    assert!(matches!(
        b.service.set_team_shared(OWNER, "other", true).await,
        Err(NetworkError::TeamNotFound)
    ));
    b.service.set_team_shared(OWNER, "team-on", true).await.unwrap();
    pair(&a, &b).await;
    let peer = a.peer_id_of(&b).await;
    let teams = a.service.remote_teams(OWNER, &peer).await.unwrap();
    assert_eq!(
        teams,
        vec![aionui_api_types::LanTeam {
            id: "team-on".into(),
            name: "Shared team".into()
        }]
    );
    b.service.set_team_shared(OWNER, "team-on", false).await.unwrap();
    assert!(a.service.remote_teams(OWNER, &peer).await.unwrap().is_empty());
    b.service.set_team_shared(OWNER, "team-on", true).await.unwrap();
    let on_b = b.peer_id_of(&a).await;
    b.service.revoke_peer(OWNER, &on_b).await.unwrap();
    assert!(a.service.remote_teams(OWNER, &peer).await.is_err());
    sqlx::query("DELETE FROM teams WHERE id = ?")
        .bind("team-on")
        .execute(b._db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)")
        .bind("team-on")
        .bind(OWNER)
        .bind("Recreated")
        .execute(b._db.pool())
        .await
        .unwrap();
    assert!(b.service.shared_teams(OWNER).await.unwrap().is_empty());
}

async fn share_codex(owner: &TestHost, requester: &TestHost) -> String {
    let peer = owner.peer_id_of(requester).await;
    owner
        .service
        .create_share(
            OWNER,
            CreateShareRequest {
                peer_id: peer,
                label: "codex".into(),
                backend: "codex".into(),
                workspace: None,
                expires_at: None,
            },
        )
        .await
        .unwrap()
        .id
}

async fn send(requester: &TestHost, owner: &TestHost, share_id: &str, content: &str) -> String {
    let peer = requester.peer_id_of(owner).await;
    requester
        .service
        .send(
            OWNER,
            SendRemoteRequest {
                peer_id: peer,
                share_id: share_id.into(),
                share_label: "codex".into(),
                content: content.into(),
                thread_id: None,
                deadline_secs: None,
            },
        )
        .await
        .unwrap()
        .id
}

async fn wait_state(host: &TestHost, id: &str, state: RemoteRequestState) -> aionui_api_types::OutboundRequestView {
    eventually(&format!("state {state:?}"), || async {
        let view = host.outbound(id).await;
        (view.state == state).then_some(view)
    })
    .await
}

#[tokio::test]
async fn pairing_requires_responder_approval_and_matching_codes() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    let on_a = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    assert_eq!(on_a.state, PeerState::PendingOutbound);
    assert_eq!(on_a.fingerprint, b.host.fingerprint().as_str());
    assert_eq!(on_a.display_name, "B");

    let on_b = b.service.list_peers(OWNER).await.unwrap();
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0].state, PeerState::PendingInbound);
    assert_eq!(on_b[0].fingerprint, a.host.fingerprint().as_str());
    assert_eq!(
        on_b[0].verification_code, on_a.verification_code,
        "both owners compare the same code"
    );

    // Pending peers cannot use anything.
    let err = b.inbound.list_shares(a.host.fingerprint()).await.unwrap_err();
    assert!(matches!(err, NetworkError::PeerUntrusted), "got {err:?}");
    let err = a.service.remote_agents(OWNER, &on_a.id).await.unwrap_err();
    assert!(
        matches!(err, NetworkError::PeerUntrusted),
        "requester side not confirmed yet: {err:?}"
    );

    b.service.approve_peer(OWNER, &on_b[0].id).await.unwrap();
    let on_a = a.service.list_peers(OWNER).await.unwrap().remove(0);
    assert_eq!(on_a.state, PeerState::Trusted);
    assert!(a.service.remote_agents(OWNER, &on_a.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn initiator_is_trusted_after_responder_approval_without_second_click() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    let on_a = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    let on_b = b.peer_id_of(&a).await;
    b.service.approve_peer(OWNER, &on_b).await.unwrap();

    let peers = a.service.list_peers(OWNER).await.unwrap();
    assert_eq!(
        peers.iter().find(|p| p.id == on_a.id).unwrap().state,
        PeerState::Trusted
    );
}

#[tokio::test]
async fn revoked_pairing_is_not_restored_by_later_approval() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    let on_a = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    let on_b = b.peer_id_of(&a).await;
    a.service.revoke_peer(OWNER, &on_a.id).await.unwrap();
    b.service.approve_peer(OWNER, &on_b).await.unwrap();
    let state = a
        .service
        .list_peers(OWNER)
        .await
        .unwrap()
        .into_iter()
        .find(|peer| peer.id == on_a.id)
        .unwrap()
        .state;
    assert_eq!(state, PeerState::Revoked);

    let (c, d) = (start_host("C").await, start_host("D").await);
    c.service.add_peer(OWNER, AddPeerRequest { url: d.url() }).await.unwrap();
    let on_d = d.peer_id_of(&c).await;
    d.service.revoke_peer(OWNER, &on_d).await.unwrap();
    assert!(matches!(d.service.approve_peer(OWNER, &on_d).await, Err(NetworkError::PeerRevoked)));
}

#[tokio::test]
async fn remote_revocation_is_reported_but_offline_is_not_revocation() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let b_on_a = a.peer_id_of(&b).await;
    b.set_listening(false).await;
    assert_eq!(
        a.service
            .list_peers(OWNER)
            .await
            .unwrap()
            .iter()
            .find(|p| p.id == b_on_a)
            .unwrap()
            .state,
        PeerState::Trusted
    );
    b.set_listening(true).await;
    b.service.revoke_peer(OWNER, &b.peer_id_of(&a).await).await.unwrap();
    assert_eq!(
        a.service
            .list_peers(OWNER)
            .await
            .unwrap()
            .iter()
            .find(|p| p.id == b_on_a)
            .unwrap()
            .state,
        PeerState::Revoked
    );
}

#[tokio::test]
async fn non_owner_users_cannot_manage_the_network() {
    let a = start_host("A").await;
    let err = a.service.list_peers("someone-else").await.unwrap_err();
    assert!(matches!(err, NetworkError::OwnerOnly));
    assert_eq!(err.http_status(), 403);
}

#[tokio::test]
async fn add_peer_rejects_non_https_addresses_and_self() {
    let a = start_host("A").await;
    for url in [
        "http://127.0.0.1:1",
        "https://u:p@127.0.0.1:1",
        "https://127.0.0.1:1/x?y=1",
    ] {
        let err = a
            .service
            .add_peer(OWNER, AddPeerRequest { url: url.into() })
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::InvalidRequest(_)), "{url}: {err:?}");
    }
    let err = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: a.url() })
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::InvalidRequest(_)), "self pairing: {err:?}");
}

#[tokio::test]
async fn shared_agent_runs_on_owner_host_and_result_reaches_requester() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let peer_on_a = a.peer_id_of(&b).await;
    assert!(
        a.service.remote_agents(OWNER, &peer_on_a).await.unwrap().is_empty(),
        "nothing shared yet"
    );
    let share = share_codex(&b, &a).await;
    let agents = a.service.remote_agents(OWNER, &peer_on_a).await.unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].share_id, share);

    let id = send(&a, &b, &share, "list the files").await;
    wait_state(&a, &id, RemoteRequestState::Running).await;
    let conversation = eventually("turn started on B", || async {
        (b.runner.turn_count() == 1).then(|| b.runner.last_conversation())
    })
    .await;
    assert_eq!(b.runner.turns.lock().unwrap()[0].1, "list the files");
    let spec = b.runner.created.lock().unwrap()[0].clone();
    assert_eq!(spec.mode, "read-only", "remote turns never run in a full-access mode");
    assert!(spec.name.contains('A'), "owner sees who asked: {}", spec.name);

    b.runner.emit(&conversation, TurnEvent::Text("hello ".into())).await;
    b.runner
        .emit(&conversation, TurnEvent::WaitingForOwner(WaitingKind::Approval))
        .await;
    let waiting = wait_state(&a, &id, RemoteRequestState::WaitingForOwner).await;
    assert_eq!(waiting.waiting_kind, Some(WaitingKind::Approval));

    b.runner.emit(&conversation, TurnEvent::Activity).await;
    b.runner.emit(&conversation, TurnEvent::Text("world".into())).await;
    b.runner.emit(&conversation, TurnEvent::Finished).await;
    let done = wait_state(&a, &id, RemoteRequestState::Succeeded).await;
    assert_eq!(done.result_text.as_deref(), Some("hello world"));
    assert_eq!(done.error_code, None);

    let inbound = b.service.list_inbound(OWNER).await.unwrap();
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].conversation_id.as_deref(), Some(conversation.as_str()));
    assert_eq!(inbound[0].peer_display_name, "A");
}

#[tokio::test]
async fn duplicate_request_never_starts_a_second_turn_and_reused_id_conflicts() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let id = send(&a, &b, &share, "do it").await;
    let row = a.outbound(&id).await;
    wait_state(&a, &id, RemoteRequestState::Running).await;

    // Delivery retry (same id, same content) → same receipt, still one turn.
    let retry = PeerSubmitRequest {
        protocol_version: PEER_CONTRACT_VERSION,
        request_id: row.request_id.clone(),
        share_id: share.clone(),
        thread_id: row.thread_id.clone(),
        content: "do it".into(),
        deadline_at: row.deadline_at,
    };
    let receipt = b.inbound.submit(a.host.fingerprint(), retry.clone()).await.unwrap();
    assert_eq!(receipt.request_id, row.request_id);
    assert_eq!(receipt.state, RemoteRequestState::Running);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(b.runner.turn_count(), 1);

    let conflict = PeerSubmitRequest {
        content: "something else".into(),
        ..retry
    };
    let err = b.inbound.submit(a.host.fingerprint(), conflict).await.unwrap_err();
    assert!(matches!(err, NetworkError::RequestConflict), "got {err:?}");
    assert_eq!(err.http_status(), 409);
}

#[tokio::test]
async fn unshare_cancels_running_turn_and_blocks_new_requests() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let id = send(&a, &b, &share, "long task").await;
    wait_state(&a, &id, RemoteRequestState::Running).await;
    let conversation = eventually("turn", || async {
        (b.runner.turn_count() == 1).then(|| b.runner.last_conversation())
    })
    .await;

    b.service.unshare(OWNER, &share).await.unwrap();
    let ended = wait_state(&a, &id, RemoteRequestState::Cancelled).await;
    assert_eq!(ended.error_code.as_deref(), Some("GRANT_REVOKED"));
    assert_eq!(b.runner.cancelled.lock().unwrap().as_slice(), [conversation]);

    let peer_on_a = a.peer_id_of(&b).await;
    assert!(a.service.remote_agents(OWNER, &peer_on_a).await.unwrap().is_empty());
    let id2 = send(&a, &b, &share, "again").await;
    let failed = wait_state(&a, &id2, RemoteRequestState::Failed).await;
    assert_eq!(failed.error_code.as_deref(), Some("SHARE_NOT_FOUND"));
    assert_eq!(b.runner.turn_count(), 1);
}

#[tokio::test]
async fn revoked_peer_is_refused_everywhere_including_pairing_replay() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    share_codex(&b, &a).await;
    let a_on_b = b.peer_id_of(&a).await;
    b.service.revoke_peer(OWNER, &a_on_b).await.unwrap();

    let peer_on_a = a.peer_id_of(&b).await;
    let err = a.service.remote_agents(OWNER, &peer_on_a).await.unwrap_err();
    assert!(matches!(err, NetworkError::PeerRevoked), "got {err:?}");
    // Pairing again from the revoked identity is refused until B forgets it.
    let err = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::PeerRevoked), "got {err:?}");
    let err = b
        .inbound
        .status(a.host.fingerprint(), "any", 0, std::time::Duration::ZERO)
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::PeerRevoked));
}

#[tokio::test]
async fn unknown_host_cannot_list_or_submit() {
    let (a, b, stranger) = (start_host("A").await, start_host("B").await, start_host("C").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let err = b.inbound.list_shares(stranger.host.fingerprint()).await.unwrap_err();
    assert!(matches!(err, NetworkError::PeerUntrusted));
    let err = b
        .inbound
        .submit(
            stranger.host.fingerprint(),
            PeerSubmitRequest {
                protocol_version: PEER_CONTRACT_VERSION,
                request_id: "r-1".into(),
                share_id: share,
                thread_id: "t-1".into(),
                content: "x".into(),
                deadline_at: now_ms() + 60_000,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::PeerUntrusted));
    assert_eq!(b.runner.turn_count(), 0);
}

#[tokio::test]
async fn requester_cancel_stops_the_owner_turn() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let id = send(&a, &b, &share, "task").await;
    wait_state(&a, &id, RemoteRequestState::Running).await;
    eventually("turn", || async { (b.runner.turn_count() == 1).then_some(()) }).await;
    a.service.cancel_outbound(OWNER, &id).await.unwrap();
    let view = wait_state(&a, &id, RemoteRequestState::Cancelled).await;
    assert_eq!(view.error_code.as_deref(), Some("CANCELLED_BY_REQUESTER"));
    assert_eq!(b.runner.cancelled.lock().unwrap().len(), 1);
    let err = a.service.cancel_outbound(OWNER, &id).await.unwrap_err();
    assert!(matches!(err, NetworkError::AlreadyFinished));
}

#[tokio::test]
async fn offline_owner_keeps_request_pending_then_delivers_once() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    b.set_listening(false).await;

    let id = send(&a, &b, &share, "when you are back").await;
    let pending = eventually("unreachable", || async {
        let view = a.outbound(&id).await;
        (!view.peer_reachable).then_some(view)
    })
    .await;
    assert_eq!(pending.state, RemoteRequestState::PendingDelivery);
    assert_eq!(b.runner.turn_count(), 0);

    b.set_listening(true).await;
    wait_state(&a, &id, RemoteRequestState::Running).await;
    let view = a.outbound(&id).await;
    assert!(view.peer_reachable);
    // B reports Running as it hands the turn to its runner, so the runner may
    // record it a moment later under load; it must still run exactly once.
    eventually("the turn to start on B", || async {
        (b.runner.turn_count() > 0).then_some(())
    })
    .await;
    assert_eq!(b.runner.turn_count(), 1);
}

#[tokio::test]
async fn restart_fails_interrupted_turns_without_rerunning_them() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let a_on_b = b.peer_id_of(&a).await;
    // A row a previous process had claimed and was running.
    let row = b
        .repo
        .insert_inbound(InsertInboundParams {
            peer_id: &a_on_b,
            share_id: &share,
            request_id: "old-1",
            thread_id: "t-1",
            content: "x",
            content_hash: "h",
            state: "queued",
            deadline_at: now_ms() + 600_000,
        })
        .await
        .unwrap();
    assert!(b.repo.claim_inbound(&row.id, "boot-previous", now_ms()).await.unwrap());

    assert_eq!(b.inbound.recover().await.unwrap(), 1);
    let row = b.repo.find_inbound(&row.id).await.unwrap().unwrap();
    assert_eq!(row.state, "failed");
    assert_eq!(row.error_code.as_deref(), Some("HOST_RESTARTED"));
    assert_eq!(b.runner.turn_count(), 0, "interrupted work is never re-run");

    // The previous process's claim cannot write anymore.
    let stale = RequestUpdate {
        state: Some("succeeded"),
        updated_at: now_ms(),
        ..Default::default()
    };
    assert!(
        !b.repo
            .update_inbound_fenced(&row.id, "boot-previous", &stale)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn expired_share_is_not_listed_and_past_deadline_submit_is_rejected() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let a_on_b = b.peer_id_of(&a).await;
    let err = b
        .service
        .create_share(
            OWNER,
            CreateShareRequest {
                peer_id: a_on_b.clone(),
                label: "codex".into(),
                backend: "codex".into(),
                workspace: None,
                expires_at: Some(now_ms() - 1),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::InvalidRequest(_)));
    let err = b
        .service
        .create_share(
            OWNER,
            CreateShareRequest {
                peer_id: a_on_b,
                label: "x".into(),
                backend: "gemini".into(),
                workspace: None,
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, NetworkError::InvalidRequest(_)),
        "unshareable backend: {err:?}"
    );

    let share = share_codex(&b, &a).await;
    let err = b
        .inbound
        .submit(
            a.host.fingerprint(),
            PeerSubmitRequest {
                protocol_version: PEER_CONTRACT_VERSION,
                request_id: "late-1".into(),
                share_id: share,
                thread_id: "t".into(),
                content: "x".into(),
                deadline_at: now_ms() - 1,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::InvalidRequest(_)));
}

#[tokio::test]
async fn follow_up_in_same_thread_reuses_the_owner_conversation() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let first = send(&a, &b, &share, "one").await;
    wait_state(&a, &first, RemoteRequestState::Running).await;
    let conversation = eventually("turn", || async {
        (b.runner.turn_count() == 1).then(|| b.runner.last_conversation())
    })
    .await;
    b.runner.emit(&conversation, TurnEvent::Finished).await;
    wait_state(&a, &first, RemoteRequestState::Succeeded).await;

    let thread = a.outbound(&first).await.thread_id;
    let peer = a.peer_id_of(&b).await;
    let second = a
        .service
        .send(
            OWNER,
            SendRemoteRequest {
                peer_id: peer,
                share_id: share,
                share_label: "codex".into(),
                content: "two".into(),
                thread_id: Some(thread),
                deadline_secs: None,
            },
        )
        .await
        .unwrap()
        .id;
    wait_state(&a, &second, RemoteRequestState::Running).await;
    eventually("second turn", || async { (b.runner.turn_count() == 2).then_some(()) }).await;
    assert_eq!(b.runner.last_conversation(), conversation);
    assert_eq!(
        b.runner.created.lock().unwrap().len(),
        1,
        "no new conversation for a follow-up"
    );
}

#[tokio::test]
async fn revocation_ends_an_open_long_poll() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    pair(&a, &b).await;
    let share = share_codex(&b, &a).await;
    let id = send(&a, &b, &share, "long task").await;
    let running = wait_state(&a, &id, RemoteRequestState::Running).await;

    // A long-poll that would otherwise wait for news well past the revocation.
    let inbound = b.inbound.clone();
    let caller = a.host.fingerprint().clone();
    let request_id = running.request_id.clone();
    let poll = tokio::spawn(async move {
        inbound
            .status(&caller, &request_id, i64::MAX, std::time::Duration::from_secs(20))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let a_on_b = b.peer_id_of(&a).await;
    let started = std::time::Instant::now();
    b.service.revoke_peer(OWNER, &a_on_b).await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), poll)
        .await
        .expect("long-poll must end soon after revocation")
        .unwrap();
    assert!(matches!(result, Err(NetworkError::PeerRevoked)), "got {result:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[tokio::test]
async fn lan_settings_can_be_resent_and_toggled_on_the_same_port() {
    let a = start_host("a").await;
    let b = start_host("b").await;
    // Re-sending "on" must not try to bind the port the listener already holds.
    a.set_listening(true).await;
    a.set_listening(true).await;
    // Off then straight back on, same port: the old socket is closed first.
    a.set_listening(false).await;
    a.set_listening(true).await;
    pair(&b, &a).await;
}

// ── ADR-016: commit-then-reveal pairing code (audit run-2 SEC-F) ──

fn some_fingerprint(seed: u8) -> aionui_peer::Fingerprint {
    aionui_peer::Fingerprint::parse(&hex::encode([seed; 32])).unwrap()
}

#[tokio::test]
async fn the_responder_commits_before_it_sees_the_initiator_nonce() {
    let b = start_host("B").await;
    let caller = some_fingerprint(7);
    let answer = b
        .inbound
        .pair(
            &caller,
            aionui_api_types::PeerPairingRequest {
                protocol_version: PEER_CONTRACT_VERSION,
                display_name: "A".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        answer.responder_commitment.len(),
        64,
        "only a commitment before the reveal"
    );
    let opened = b
        .inbound
        .reveal(
            &caller,
            aionui_api_types::PeerPairingReveal {
                nonce: hex::encode([1u8; 32]),
            },
        )
        .await
        .unwrap();
    let nonce = hex::decode(&opened.responder_nonce).unwrap();
    assert_eq!(
        aionui_network::pairing_commitment(&nonce),
        answer.responder_commitment,
        "the revealed nonce is the one committed to"
    );
}

#[tokio::test]
async fn a_known_caller_cannot_rekey_its_pairing() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    let on_a = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    let err = b
        .inbound
        .pair(
            a.host.fingerprint(),
            aionui_api_types::PeerPairingRequest {
                protocol_version: PEER_CONTRACT_VERSION,
                display_name: "A".into(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::InvalidRequest(_)), "got {err:?}");
    let again = a
        .service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    assert_eq!(
        again.verification_code, on_a.verification_code,
        "re-adding never re-keys"
    );
    let on_b = b.service.list_peers(OWNER).await.unwrap();
    assert_eq!(on_b[0].verification_code, on_a.verification_code);
}

#[tokio::test]
async fn a_reveal_without_an_exchange_records_nothing() {
    let b = start_host("B").await;
    let err = b
        .inbound
        .reveal(
            &some_fingerprint(9),
            aionui_api_types::PeerPairingReveal {
                nonce: hex::encode([2u8; 32]),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::InvalidRequest(_)), "got {err:?}");
    assert!(b.service.list_peers(OWNER).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_version_one_pairing_request_is_refused() {
    let b = start_host("B").await;
    let err = b
        .inbound
        .pair(
            &some_fingerprint(8),
            aionui_api_types::PeerPairingRequest {
                protocol_version: 1,
                display_name: "A".into(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetworkError::VersionUnsupported), "got {err:?}");
}

#[tokio::test]
async fn an_expired_pending_pairing_cannot_be_approved() {
    let (a, b) = (start_host("A").await, start_host("B").await);
    a.service
        .add_peer(OWNER, AddPeerRequest { url: b.url() })
        .await
        .unwrap();
    sqlx::query("UPDATE network_peers SET updated_at = 0")
        .execute(b._db.pool())
        .await
        .unwrap();
    let id = b.peer_id_of(&a).await;
    let err = b.service.approve_peer(OWNER, &id).await.unwrap_err();
    assert!(matches!(err, NetworkError::PeerNotFound), "got {err:?}");
    assert!(
        b.service.list_peers(OWNER).await.unwrap().is_empty(),
        "expired requests are removed"
    );
}
