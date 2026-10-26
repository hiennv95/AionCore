mod support;

use aionui_api_types::{
    AddPeerRequest, CreateShareRequest, PEER_CONTRACT_VERSION, PeerState, PeerSubmitRequest, RemoteRequestState,
    SendRemoteRequest, WaitingKind,
};
use aionui_common::now_ms;
use aionui_db::{InsertInboundParams, RequestUpdate};
use aionui_network::{NetworkError, TurnEvent};
use support::{OWNER, TestHost, eventually, pair, start_host};

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
async fn pairing_requires_both_owners_and_matching_codes() {
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
    a.service.approve_peer(OWNER, &on_a.id).await.unwrap();
    assert!(a.service.remote_agents(OWNER, &on_a.id).await.unwrap().is_empty());
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
