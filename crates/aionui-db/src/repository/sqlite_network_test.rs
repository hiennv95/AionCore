use super::SqliteNetworkRepository;
use crate::error::DbError;
use crate::init_database_memory;
use crate::repository::network::{
    INetworkRepository, InsertInboundParams, InsertOutboundParams, InsertPeerParams, InsertShareParams,
    LanMessageEnqueue, OutboundUpdate, RequestUpdate, UpdatePeerParams,
};

const FP: &str = "aa00000000000000000000000000000000000000000000000000000000000000";

#[tokio::test]
async fn lan_receipts_and_outbox_survive_database_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host.sqlite");
    let db = crate::init_database(&path).await.unwrap();
    let repo = SqliteNetworkRepository::new(db.pool().clone());
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "A",
            display_name: "A",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'A', 'team-a', 'active')")
        .execute(db.pool()).await.unwrap();
    let message = crate::models::MailboxMessageRow {
        id: "receipt-mail".into(),
        team_id: "team".into(),
        to_agent_id: "leader".into(),
        from_agent_id: "remote".into(),
        msg_type: "message".into(),
        content: "hello".into(),
        summary: None,
        files: None,
        read: false,
        created_at: 1,
    };
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Inserted
    );
    for id in ["first", "second"] {
        assert!(
            repo.enqueue_lan_team_outbound(id, "owner", "team", &peer.id, "team-a", id)
                .await
                .unwrap()
        );
    }
    assert!(repo.defer_lan_team_outbound("first", 100).await.unwrap());
    db.close().await;
    drop(repo);
    drop(db);

    let db = crate::init_database(&path).await.unwrap();
    let repo = SqliteNetworkRepository::new(db.pool().clone());
    assert_eq!(
        repo.teams_with_unread_lan_messages("owner").await.unwrap(),
        vec!["team"]
    );
    assert!(repo.teams_with_unread_lan_messages("other").await.unwrap().is_empty());
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Duplicate
    );
    assert!(repo.pending_lan_team_outbound(99, 8).await.unwrap().is_empty());
    assert_eq!(
        repo.pending_lan_team_outbound(100, 8)
            .await
            .unwrap()
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["first"]
    );
    assert!(repo.finish_lan_team_outbound("first", "delivered").await.unwrap());
    assert_eq!(
        repo.pending_lan_team_outbound(100, 8)
            .await
            .unwrap()
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["second"]
    );
    sqlx::query("UPDATE mailbox SET read = 1 WHERE id = 'receipt-mail'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.teams_with_unread_lan_messages("owner").await.unwrap().is_empty());
}

#[tokio::test]
async fn lan_outbound_and_mailbox_are_recorded_together() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "A",
            display_name: "A",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'A', 'team-a', 'active')")
        .execute(db.pool()).await.unwrap();
    let message = crate::models::MailboxMessageRow {
        id: "message-1".into(),
        team_id: "team".into(),
        to_agent_id: "remote".into(),
        from_agent_id: "leader".into(),
        msg_type: "message".into(),
        content: "hello".into(),
        summary: None,
        files: None,
        read: false,
        created_at: 1,
    };
    assert!(
        !repo
            .enqueue_lan_team_outbound_with_mailbox("other", &peer.id, "team-a", &message)
            .await
            .unwrap()
    );
    sqlx::query("CREATE TRIGGER fail_outbound_mailbox BEFORE INSERT ON mailbox BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        repo.enqueue_lan_team_outbound_with_mailbox("owner", &peer.id, "team-a", &message)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_team_outbox")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DROP TRIGGER fail_outbound_mailbox")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        repo.enqueue_lan_team_outbound_with_mailbox("owner", &peer.id, "team-a", &message)
            .await
            .unwrap()
    );
    let pair: (String, String) = sqlx::query_as(
        "SELECT mailbox.id, lan_team_outbox.id FROM mailbox JOIN lan_team_outbox ON mailbox.id = lan_team_outbox.id",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(pair, ("message-1".into(), "message-1".into()));
    assert_eq!(
        repo.lan_team_delivery_statuses("owner", "team").await.unwrap(),
        vec![("message-1".into(), "pending".into())]
    );
    assert!(
        repo.lan_team_delivery_statuses("other", "team")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.lan_team_delivery_statuses("owner", "other-team")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(repo.finish_lan_team_outbound("message-1", "delivered").await.unwrap());
    assert_eq!(
        repo.lan_team_delivery_statuses("owner", "team").await.unwrap(),
        vec![("message-1".into(), "delivered".into())]
    );
    assert!(repo.revoke_peer_and_memberships(&peer.id, None).await.unwrap());
    let mut later = message;
    later.id = "message-2".into();
    assert!(
        !repo
            .enqueue_lan_team_outbound_with_mailbox("owner", &peer.id, "team-a", &later)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn lan_outbox_retries_do_not_block_other_peers_or_reorder_conversation() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let mut peers = Vec::new();
    for fingerprint in ["A", "B"] {
        let peer = repo
            .insert_peer(InsertPeerParams {
                fingerprint,
                display_name: fingerprint,
                peer_url: None,
                state: "trusted",
                verification_code: "123456",
            })
            .await
            .unwrap();
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', ?, ?, 'active')")
            .bind(fingerprint).bind(format!("team-{fingerprint}")).execute(db.pool()).await.unwrap();
        peers.push(peer);
    }
    for (id, peer, remote) in [
        ("a-first", &peers[0], "team-A"),
        ("a-second", &peers[0], "team-A"),
        ("b-first", &peers[1], "team-B"),
    ] {
        assert!(
            repo.enqueue_lan_team_outbound(id, "owner", "team", &peer.id, remote, id)
                .await
                .unwrap()
        );
    }
    let ids = |rows: Vec<crate::LanTeamOutboxRow>| rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    assert_eq!(
        ids(repo.pending_lan_team_outbound(0, 8).await.unwrap()),
        vec!["a-first", "b-first"]
    );
    assert!(repo.defer_lan_team_outbound("a-first", 100).await.unwrap());
    assert_eq!(
        ids(repo.pending_lan_team_outbound(50, 8).await.unwrap()),
        vec!["b-first"]
    );
    assert!(repo.finish_lan_team_outbound("b-first", "delivered").await.unwrap());
    assert!(repo.pending_lan_team_outbound(50, 8).await.unwrap().is_empty());
    assert_eq!(
        ids(repo.pending_lan_team_outbound(100, 8).await.unwrap()),
        vec!["a-first"]
    );
    assert!(repo.finish_lan_team_outbound("a-first", "delivered").await.unwrap());
    assert_eq!(
        ids(repo.pending_lan_team_outbound(100, 8).await.unwrap()),
        vec!["a-second"]
    );
}

#[tokio::test]
async fn lan_team_message_receipt_is_atomic_idempotent_and_rechecks_authorization() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "A",
            display_name: "A",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'A', 'team-a', 'active')")
        .execute(db.pool()).await.unwrap();
    let mut message = crate::models::MailboxMessageRow {
        id: "mail-1".into(),
        team_id: "team".into(),
        to_agent_id: "leader".into(),
        from_agent_id: "remote".into(),
        msg_type: "message".into(),
        content: "hello".into(),
        summary: None,
        files: None,
        read: false,
        created_at: 1,
    };
    assert_eq!(
        repo.enqueue_lan_team_message("other", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Unauthorized
    );
    sqlx::query("CREATE TRIGGER fail_lan_receipt BEFORE INSERT ON lan_team_message_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DROP TRIGGER fail_lan_receipt")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Inserted
    );
    message.id = "mail-2".into();
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Duplicate
    );
    message.content = "changed".into();
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Conflict
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailbox")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(repo.revoke_peer_and_memberships(&peer.id, None).await.unwrap());
    assert_eq!(
        repo.enqueue_lan_team_message("owner", "A", "team-a", "request", &message)
            .await
            .unwrap(),
        LanMessageEnqueue::Unauthorized
    );
}

#[tokio::test]
async fn lan_team_message_authorization_requires_active_shared_membership_and_trust() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "A",
            display_name: "A",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    assert!(
        repo.authorized_lan_team_member("owner", "team", "A", "team-a")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'A', 'team-a', 'active')")
        .execute(db.pool()).await.unwrap();
    assert_eq!(
        repo.authorized_lan_team_member("owner", "team", "A", "team-a")
            .await
            .unwrap(),
        Some(peer.id.clone())
    );
    let active = repo.active_lan_team_members("owner").await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(
        (&active[0].team_id, &active[0].peer_id, &active[0].remote_team_id),
        (&"team".to_owned(), &peer.id, &"team-a".to_owned())
    );
    assert!(repo.active_lan_team_members("other").await.unwrap().is_empty());
    for (owner, team, fingerprint, remote) in [
        ("other", "team", "A", "team-a"),
        ("owner", "wrong", "A", "team-a"),
        ("owner", "team", "B", "team-a"),
        ("owner", "team", "A", "wrong"),
    ] {
        assert!(
            repo.authorized_lan_team_member(owner, team, fingerprint, remote)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        repo.compare_and_set_peer_state(&peer.id, "trusted", "revoked")
            .await
            .unwrap()
    );
    assert!(repo.active_lan_team_members("owner").await.unwrap().is_empty());
    assert!(
        repo.authorized_lan_team_member("owner", "team", "A", "team-a")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.compare_and_set_peer_state(&peer.id, "revoked", "trusted")
            .await
            .unwrap()
    );
    sqlx::query("UPDATE lan_team_members SET state = 'revoked' WHERE team_id = 'team'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        repo.authorized_lan_team_member("owner", "team", "A", "team-a")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE lan_team_members SET state = 'active' WHERE team_id = 'team'")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", false).await.unwrap();
    assert!(
        repo.authorized_lan_team_member("owner", "team", "A", "team-a")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn participant_roster_requires_matching_consent_and_current_trust() {
    let (repo, db) = repo().await;
    sqlx::query(
        "INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team-b', 'owner', 'Team', 1, 1)",
    )
    .execute(db.pool())
    .await
    .unwrap();
    repo.set_team_shared("owner", "team-b", true).await.unwrap();
    let mut peers = Vec::new();
    for fingerprint in ["A", "C"] {
        peers.push(
            repo.insert_peer(InsertPeerParams {
                fingerprint,
                display_name: fingerprint,
                peer_url: None,
                state: "trusted",
                verification_code: "123456",
            })
            .await
            .unwrap(),
        );
    }
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team-b', 'C', 'team-c', 'active')")
        .execute(db.pool()).await.unwrap();
    assert!(
        !repo
            .record_team_poll_consent("owner", "team-b", "A", "incomplete", r#"["A","B"]"#)
            .await
            .unwrap()
    );
    assert!(
        repo.team_poll_consent("owner", "A", "incomplete")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("DELETE FROM lan_team_members WHERE team_id = 'team-b' AND fingerprint = 'C'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        repo.record_team_poll_consent("owner", "team-b", "A", "invite", r#"["A","B","C"]"#)
            .await
            .unwrap()
    );
    let members = vec![
        ("A".into(), "team-a".into()),
        ("B".into(), "team-b".into()),
        ("C".into(), "team-c".into()),
    ];
    assert!(
        !repo
            .apply_team_poll_membership("other", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &members[..2])
            .await
            .unwrap()
    );
    let wrong_team = vec![
        ("A".into(), "team-a".into()),
        ("B".into(), "wrong".into()),
        ("C".into(), "team-c".into()),
    ];
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &wrong_team)
            .await
            .unwrap()
    );
    assert!(
        repo.compare_and_set_peer_state(&peers[1].id, "trusted", "revoked")
            .await
            .unwrap()
    );
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
    assert!(
        repo.compare_and_set_peer_state(&peers[1].id, "revoked", "trusted")
            .await
            .unwrap()
    );
    sqlx::query("CREATE TRIGGER fail_team_member_insert BEFORE INSERT ON lan_team_members WHEN NEW.fingerprint = 'C' BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        repo.apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_team_members")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DROP TRIGGER fail_team_member_insert")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        repo.apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
    let stored: Vec<(String, String)> = sqlx::query_as("SELECT fingerprint, remote_team_id FROM lan_team_members WHERE team_id = 'team-b' AND state = 'active' ORDER BY fingerprint")
        .fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        stored,
        vec![("A".into(), "team-a".into()), ("C".into(), "team-c".into())]
    );
    assert!(
        repo.record_team_poll_consent("owner", "team-b", "A", "invite", r#"["A","B","C"]"#)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE lan_team_members SET remote_team_id = 'changed' WHERE fingerprint = 'C'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
    assert!(repo.revoke_peer_and_memberships(&peers[1].id, None).await.unwrap());
    assert!(
        !repo
            .apply_team_poll_membership("owner", "A", "invite", "B", &members)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn team_poll_consent_and_local_invitation_are_serialized() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "A",
            display_name: "A",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    let participants = r#"["A","B"]"#;
    assert!(
        repo.record_team_poll_consent("owner", "team", "A", "remote", participants)
            .await
            .unwrap()
    );
    assert!(
        repo.record_team_poll_consent("owner", "team", "A", "remote", participants)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .record_team_poll_consent("owner", "team", "A", "other", participants)
            .await
            .unwrap()
    );
    assert!(matches!(
        repo.create_team_invitation("owner", "team", "local", "B", &peer.id)
            .await,
        Err(DbError::Conflict(_))
    ));
    assert!(repo.remove_team_poll_consent("owner", "A", "remote").await.unwrap());
    repo.create_team_invitation("owner", "team", "local", "B", &peer.id)
        .await
        .unwrap();
    assert!(
        !repo
            .record_team_poll_consent("owner", "team", "A", "remote", participants)
            .await
            .unwrap()
    );
    assert!(
        repo.decide_team_invitation("owner", "local", "A", false, None)
            .await
            .unwrap()
    );
    assert!(
        repo.record_team_poll_consent("owner", "team", "A", "remote", participants)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn completing_team_invitation_requires_current_unanimous_trust_and_is_atomic() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let peer = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "B",
            display_name: "B",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    repo.create_team_invitation("owner", "team", "invite", "A", &peer.id)
        .await
        .unwrap();
    assert!(
        repo.decide_team_invitation("owner", "invite", "A", true, Some("team"))
            .await
            .unwrap()
    );
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    assert!(
        repo.decide_team_invitation("owner", "invite", "B", true, Some("team-b"))
            .await
            .unwrap()
    );
    let participants = r#"["A","B"]"#;
    assert!(
        repo.record_team_pair_attestation("owner", "invite", "A", participants, true, 10)
            .await
            .unwrap()
    );
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    assert!(
        repo.record_team_pair_attestation("owner", "invite", "B", participants, false, 10)
            .await
            .unwrap()
    );
    assert!(!repo.complete_team_invitation("other", "invite", "A", 10).await.unwrap());
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 11).await.unwrap());
    assert!(
        repo.compare_and_set_peer_state(&peer.id, "trusted", "revoked")
            .await
            .unwrap()
    );
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_team_members WHERE team_id = 'team'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(
        repo.compare_and_set_peer_state(&peer.id, "revoked", "trusted")
            .await
            .unwrap()
    );
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'C', 'team-c', 'active')")
        .execute(db.pool()).await.unwrap();
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    sqlx::query("DELETE FROM lan_team_members WHERE team_id = 'team' AND fingerprint = 'C'")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_team_member_insert BEFORE INSERT ON lan_team_members BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        .execute(db.pool()).await.unwrap();
    assert!(repo.complete_team_invitation("owner", "invite", "A", 10).await.is_err());
    let state: String = sqlx::query_scalar("SELECT state FROM lan_team_invitations WHERE id = 'invite'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(state, "pending");
    sqlx::query("DROP TRIGGER fail_team_member_insert")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    assert!(!repo.complete_team_invitation("owner", "invite", "A", 10).await.unwrap());
    let member: (String, String, String) =
        sqlx::query_as("SELECT fingerprint, remote_team_id, state FROM lan_team_members WHERE team_id = 'team'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(member, ("B".into(), "team-b".into(), "active".into()));
    let state: String = sqlx::query_scalar("SELECT state FROM lan_team_invitations WHERE id = 'invite'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(state, "completed");
}

#[tokio::test]
async fn team_invitation_votes_are_isolated_serialized_and_final_after_rejection() {
    let (repo, db) = repo().await;
    sqlx::query("INSERT INTO teams (id, user_id, name, created_at, updated_at) VALUES ('team', 'owner', 'Team', 1, 1)")
        .execute(db.pool())
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", true).await.unwrap();
    let candidate = repo
        .insert_peer(InsertPeerParams {
            fingerprint: "C",
            display_name: "C",
            peer_url: None,
            state: "trusted",
            verification_code: "123456",
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES ('team', 'B', 'team-b', 'active'), ('team', 'D', 'team-d', 'revoked')")
        .execute(db.pool()).await.unwrap();
    assert!(matches!(
        repo.create_team_invitation("other", "team", "wrong-owner", "A", &candidate.id)
            .await,
        Err(DbError::NotFound(_))
    ));
    repo.create_team_invitation("owner", "team", "invite", "A", &candidate.id)
        .await
        .unwrap();
    assert!(matches!(
        repo.create_team_invitation("owner", "team", "simultaneous", "A", &candidate.id)
            .await,
        Err(DbError::Conflict(_))
    ));
    assert!(repo.team_invitation_votes("other", "invite").await.unwrap().is_empty());
    assert!(
        repo.team_invitation_conversations("other", "invite")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !repo
            .decide_team_invitation("other", "invite", "A", true, Some("team"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("owner", "invite", "D", true, Some("team"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("owner", "invite", "B", true, Some("wrong-team"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("owner", "invite", "C", true, None)
            .await
            .unwrap()
    );
    assert!(
        repo.decide_team_invitation("owner", "invite", "A", true, Some("team"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.team_invitation_conversations("owner", "invite").await.unwrap(),
        vec![("A".into(), "team".into())]
    );
    assert!(
        repo.decide_team_invitation("owner", "invite", "B", false, None)
            .await
            .unwrap()
    );
    assert!(
        repo.decide_team_invitation("owner", "invite", "B", false, None)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("other", "invite", "B", false, None)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("owner", "invite", "A", false, None)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .decide_team_invitation("owner", "invite", "C", true, Some("team-c"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.team_invitation_votes("owner", "invite").await.unwrap(),
        vec![
            ("A".into(), "approved".into()),
            ("B".into(), "rejected".into()),
            ("C".into(), "pending".into())
        ]
    );
    repo.create_team_invitation("owner", "team", "retry", "A", &candidate.id)
        .await
        .unwrap();
    repo.set_team_shared("owner", "team", false).await.unwrap();
    assert!(
        !repo
            .decide_team_invitation("owner", "retry", "A", true, Some("team"))
            .await
            .unwrap()
    );
    repo.set_team_shared("owner", "team", true).await.unwrap();
    repo.create_team_invitation("owner", "team", "after-unshare", "A", &candidate.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn peer_state_compare_and_set_does_not_overwrite_a_newer_decision() {
    let (repo, _db) = repo().await;
    let (peer, _) = peer_and_share(&repo).await;
    assert!(
        repo.compare_and_set_peer_state(&peer, "trusted", "revoked")
            .await
            .unwrap()
    );
    assert!(
        !repo
            .compare_and_set_peer_state(&peer, "trusted", "pending_outbound")
            .await
            .unwrap()
    );
    assert_eq!(repo.find_peer(&peer).await.unwrap().unwrap().state, "revoked");
    assert!(!repo.revoke_peer_and_memberships(&peer, Some("trusted")).await.unwrap());
}

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
