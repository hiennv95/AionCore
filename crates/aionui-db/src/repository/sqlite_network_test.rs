use super::SqliteNetworkRepository;
use crate::error::DbError;
use crate::init_database_memory;
use crate::repository::network::{
    INetworkRepository, InsertInboundParams, InsertOutboundParams, InsertPeerParams, InsertShareParams, OutboundUpdate,
    RequestUpdate, UpdatePeerParams,
};

const FP: &str = "aa00000000000000000000000000000000000000000000000000000000000000";

async fn repo() -> (SqliteNetworkRepository, crate::Database) {
    let db = init_database_memory().await.unwrap();
    (SqliteNetworkRepository::new(db.pool().clone()), db)
}

async fn peer_and_share(repo: &SqliteNetworkRepository) -> (String, String) {
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: FP,
            display_name: "B",
            peer_url: Some("https://10.0.0.2:25820"),
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    let share = repo
        .insert_share(InsertShareParams {
            peer_id: &peer.id,
            label: "codex",
            backend: "codex",
            mode: "read-only",
            workspace: "/tmp/ws",
            expires_at: None,
        })
        .await
        .unwrap();
    (peer.id, share.id)
}

fn inbound<'a>(peer: &'a str, share: &'a str, request_id: &'a str) -> InsertInboundParams<'a> {
    InsertInboundParams {
        peer_id: peer,
        share_id: share,
        request_id,
        thread_id: "t1",
        content: "hello",
        content_hash: "h1",
        state: "queued",
        deadline_at: i64::MAX,
    }
}

#[tokio::test]
async fn peer_fingerprint_is_unique() {
    let (repo, _db) = repo().await;
    peer_and_share(&repo).await;
    let err = repo
        .insert_peer(InsertPeerParams {
            fingerprint: FP,
            display_name: "B2",
            peer_url: None,
            state: "pending_inbound",
            verification_code: "1",
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "got {err:?}");
}

#[tokio::test]
async fn update_peer_changes_state_and_missing_peer_is_not_found() {
    let (repo, _db) = repo().await;
    let (peer, _) = peer_and_share(&repo).await;
    repo.update_peer(
        &peer,
        UpdatePeerParams {
            state: Some("revoked"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(repo.find_peer(&peer).await.unwrap().unwrap().state, "revoked");
    let err = repo.update_peer("nope", UpdatePeerParams::default()).await.unwrap_err();
    assert!(matches!(err, DbError::NotFound(_)));
}

#[tokio::test]
async fn duplicate_request_id_per_peer_conflicts() {
    let (repo, _db) = repo().await;
    let (peer, share) = peer_and_share(&repo).await;
    repo.insert_inbound(inbound(&peer, &share, "r1")).await.unwrap();
    let err = repo.insert_inbound(inbound(&peer, &share, "r1")).await.unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "got {err:?}");
}

#[tokio::test]
async fn claim_is_exclusive_and_fencing_rejects_stale_owner() {
    let (repo, _db) = repo().await;
    let (peer, share) = peer_and_share(&repo).await;
    let row = repo.insert_inbound(inbound(&peer, &share, "r1")).await.unwrap();
    assert!(repo.claim_inbound(&row.id, "boot-a", 1).await.unwrap());
    assert!(
        !repo.claim_inbound(&row.id, "boot-b", 2).await.unwrap(),
        "second claim must fail"
    );

    let update = RequestUpdate {
        result_text: Some("partial"),
        updated_at: 3,
        ..Default::default()
    };
    assert!(!repo.update_inbound_fenced(&row.id, "boot-b", &update).await.unwrap());
    assert!(repo.update_inbound_fenced(&row.id, "boot-a", &update).await.unwrap());

    let done = RequestUpdate {
        state: Some("succeeded"),
        finished_at: Some(4),
        updated_at: 4,
        ..Default::default()
    };
    assert!(repo.update_inbound_fenced(&row.id, "boot-a", &done).await.unwrap());
    // Terminal rows are final, even for the owner.
    assert!(!repo.update_inbound_fenced(&row.id, "boot-a", &update).await.unwrap());
    let row = repo.find_inbound(&row.id).await.unwrap().unwrap();
    assert_eq!(row.state, "succeeded");
    assert_eq!(row.result_text.as_deref(), Some("partial"));
    assert_eq!(row.version, 4, "insert + claim + 2 updates");
}

#[tokio::test]
async fn cancel_request_only_applies_to_live_rows() {
    let (repo, _db) = repo().await;
    let (peer, share) = peer_and_share(&repo).await;
    let row = repo.insert_inbound(inbound(&peer, &share, "r1")).await.unwrap();
    assert!(repo.request_inbound_cancel(&row.id, 1).await.unwrap());
    let update = RequestUpdate {
        state: Some("cancelled"),
        updated_at: 2,
        ..Default::default()
    };
    assert!(repo.update_inbound_if_state(&row.id, "queued", &update).await.unwrap());
    assert!(!repo.request_inbound_cancel(&row.id, 3).await.unwrap());
}

#[tokio::test]
async fn thread_conversation_and_state_counts() {
    let (repo, _db) = repo().await;
    let (peer, share) = peer_and_share(&repo).await;
    let row = repo.insert_inbound(inbound(&peer, &share, "r1")).await.unwrap();
    assert_eq!(repo.find_thread_conversation(&peer, &share, "t1").await.unwrap(), None);
    repo.claim_inbound(&row.id, "boot", 1).await.unwrap();
    repo.update_inbound_fenced(
        &row.id,
        "boot",
        &RequestUpdate {
            conversation_id: Some("conv-1"),
            updated_at: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        repo.find_thread_conversation(&peer, &share, "t1")
            .await
            .unwrap()
            .as_deref(),
        Some("conv-1")
    );
    assert_eq!(
        repo.count_inbound_in_states(Some(&peer), &["queued", "running"])
            .await
            .unwrap(),
        1
    );
    assert_eq!(repo.list_inbound_in_states(&["queued"]).await.unwrap().len(), 0);
}

#[tokio::test]
async fn share_revoke_is_once() {
    let (repo, _db) = repo().await;
    let (_, share) = peer_and_share(&repo).await;
    assert!(repo.revoke_share(&share, 5).await.unwrap());
    assert!(!repo.revoke_share(&share, 6).await.unwrap());
    assert_eq!(repo.find_share(&share).await.unwrap().unwrap().revoked_at, Some(5));
}

#[tokio::test]
async fn outbound_terminal_row_is_final() {
    let (repo, _db) = repo().await;
    let (peer, _) = peer_and_share(&repo).await;
    let row = repo
        .insert_outbound(InsertOutboundParams {
            user_id: "u1",
            peer_id: &peer,
            share_id: "remote-share",
            share_label: "codex",
            request_id: "req-1",
            thread_id: "t1",
            content: "hi",
            deadline_at: 10,
        })
        .await
        .unwrap();
    assert_eq!(row.state, "pending_delivery");
    let finish = OutboundUpdate {
        request: RequestUpdate {
            state: Some("succeeded"),
            result_text: Some("done"),
            updated_at: 2,
            ..Default::default()
        },
        remote_version: Some(5),
        ..Default::default()
    };
    repo.update_outbound(&row.id, &finish).await.unwrap();
    let reopen = OutboundUpdate {
        request: RequestUpdate {
            state: Some("running"),
            updated_at: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    repo.update_outbound(&row.id, &reopen).await.unwrap();
    let row = repo.find_outbound(&row.id).await.unwrap().unwrap();
    assert_eq!(row.state, "succeeded");
    assert_eq!(row.remote_version, 5);
    assert_eq!(repo.list_outbound("u1", 10).await.unwrap().len(), 1);
    assert_eq!(repo.list_outbound("u2", 10).await.unwrap().len(), 0);
}
