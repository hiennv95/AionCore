use std::process::ExitCode;

use aionui_auth::AccountError;
use aionui_db::DbError;
use aionui_db::models::{User, UserStatus, UserType};
use aionui_db::{IUserRepository, SqliteUserRepository, init_database_memory};

use super::{
    acquire_exclusive, apply_user_status, check_target, format_user_lines, map_account_error, parse_stdin_password,
};
use crate::commands::error::CliBoundaryCode;

// Security: the `user list` rendering must never surface `password_hash`,
// `jwt_secret`, or `encryption_secret`, even when all are populated. Adding a
// leaking column here should turn this test red.
//
// The account-mutation behaviour (default vs named user, hashing, validation)
// lives in `aionui-auth`'s `set_local_password` and is covered by
// `crates/aionui-auth/src/account_test.rs`; this file only guards the CLI's
// presentation layer.
#[test]
fn format_user_lines_never_leaks_secrets() {
    let user = User {
        id: "u-1".to_owned(),
        user_type: UserType::Local,
        external_user_id: None,
        username: Some("alice".to_owned()),
        email: Some("a@example.com".to_owned()),
        password_hash: Some("$2b$12$SUPERSECRETHASHVALUE".to_owned()),
        avatar_path: None,
        jwt_secret: Some("TOPSECRETJWTKEY".to_owned()),
        encryption_secret: Some("TOPSECRETENCKEY".to_owned()),
        status: UserStatus::Active,
        session_generation: 0,
        created_at: 111,
        updated_at: 222,
        last_login: Some(333),
    };

    let joined = format_user_lines(&[user]).join("\n");

    // Non-sensitive fields render.
    assert!(joined.contains("u-1"));
    assert!(joined.contains("alice"));
    assert!(joined.contains("local"));
    assert!(joined.contains("active"));
    // Sensitive fields must never appear.
    assert!(!joined.contains("SUPERSECRETHASHVALUE"));
    assert!(!joined.contains("$2b$12$"));
    assert!(!joined.contains("TOPSECRETJWTKEY"));
    assert!(!joined.contains("TOPSECRETENCKEY"));
}

// End-to-end over a real in-memory DB: the seed user shows up in the listing,
// and a secret it carries is not leaked by the renderer.
#[tokio::test]
async fn list_lines_include_seed_user_without_secrets() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteUserRepository::new(db.pool().clone());

    // A bare init leaves `jwt_secret` NULL, which would make the leak assertion
    // below vacuous. Seed a real secret onto the system user first so the
    // renderer is actually exercised against a populated, sensitive column.
    let seed = repo.get_system_user().await.unwrap().expect("seed system user present");
    let secret = "SEEDED-JWT-SECRET-VALUE";
    repo.update_jwt_secret(&seed.id, secret).await.unwrap();

    let users = repo.list_users().await.unwrap();
    let joined = format_user_lines(&users).join("\n");

    assert!(joined.contains("system_default_user"));
    assert!(
        !joined.contains(secret),
        "the system user's jwt secret must never appear in the listing"
    );
}

// Happy path: disabling an active account flips its status AND revokes live
// sessions (session_generation bumps once); re-enabling restores login without
// a second bump.
#[tokio::test]
async fn disable_then_enable_flips_status_and_revokes_sessions_once() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteUserRepository::new(db.pool().clone());
    let created = repo.create_user("carol", "hash").await.unwrap();
    assert_eq!(created.status, UserStatus::Active);
    let gen0 = created.session_generation;

    let label = apply_user_status(&repo, "carol", UserStatus::Disabled).await.unwrap();
    assert!(label.contains("carol"));
    assert!(label.contains(&created.id));
    let disabled = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(disabled.status, UserStatus::Disabled);
    assert_eq!(
        disabled.session_generation,
        gen0 + 1,
        "disabling must revoke live sessions by bumping the generation"
    );

    apply_user_status(&repo, "carol", UserStatus::Active).await.unwrap();
    let enabled = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(enabled.status, UserStatus::Active);
    assert_eq!(
        enabled.session_generation,
        gen0 + 1,
        "enabling must NOT bump the generation again"
    );
}

// Bad path: an unknown username is a usage error (CLI_USER_NOT_FOUND, exit 2),
// not an internal database failure.
#[tokio::test]
async fn disable_unknown_user_maps_to_not_found() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteUserRepository::new(db.pool().clone());

    let err = apply_user_status(&repo, "ghost", UserStatus::Disabled)
        .await
        .unwrap_err();
    assert_eq!(err.code(), CliBoundaryCode::CliUserNotFound);
    assert_eq!(err.exit_code(), ExitCode::from(2));
}

// The domain error maps onto the right CLI boundary code and exit class: a bad
// username or weak password is a config-class usage error (exit 2), while a
// hashing or database failure is internal-class (exit 1). Locking the exit code
// too, because callers script on it.
#[test]
fn map_account_error_classifies_by_category() {
    let invalid_username = map_account_error(AccountError::InvalidUsername("bad name".to_owned()));
    assert_eq!(invalid_username.code(), CliBoundaryCode::CliUserInputInvalid);
    assert_eq!(invalid_username.exit_code(), ExitCode::from(2));

    let weak = map_account_error(AccountError::WeakPassword("too short".to_owned()));
    assert_eq!(weak.code(), CliBoundaryCode::CliUserInputInvalid);
    assert_eq!(weak.exit_code(), ExitCode::from(2));

    // An already-taken username is a config-class usage error (exit 2), NOT an
    // internal database failure — the operator can act on it.
    let exists = map_account_error(AccountError::AlreadyExists("alice".to_owned()));
    assert_eq!(exists.code(), CliBoundaryCode::CliUserAlreadyExists);
    assert_eq!(exists.exit_code(), ExitCode::from(2));

    let hash = map_account_error(AccountError::Hash);
    assert_eq!(hash.code(), CliBoundaryCode::CliUserHashFailed);
    assert_eq!(hash.exit_code(), ExitCode::from(1));

    let db = map_account_error(AccountError::Db(DbError::NotFound("x".to_owned())));
    assert_eq!(db.code(), CliBoundaryCode::CliUserDatabaseFailed);
    assert_eq!(db.exit_code(), ExitCode::from(1));
}

// A database error maps to the stable database-failed code and must NOT leak the
// inner DbError text (which can carry paths/SQL detail) onto the stderr line.
// This is the one error arm with a leak dimension, so it is locked explicitly.
#[test]
fn map_account_error_db_does_not_leak_inner_detail() {
    let err = map_account_error(AccountError::Db(DbError::NotFound(
        "system_default_user row detail that must not leak".to_owned(),
    )));

    assert_eq!(err.code(), CliBoundaryCode::CliUserDatabaseFailed);
    let line = err.stderr_line();
    assert!(line.contains("CLI_USER_DATABASE_FAILED"));
    assert!(
        !line.contains("must not leak"),
        "inner DbError detail must never reach the boundary line: {line}"
    );
}

// The stdin parser strips exactly ONE trailing newline and preserves every other
// byte. A trailing space is part of the password and must survive — a regression
// to trim_end() would silently corrupt such a password.
#[test]
fn parse_stdin_password_strips_one_newline_and_preserves_bytes() {
    assert_eq!(parse_stdin_password("plain-pass\n").unwrap(), "plain-pass");
    assert_eq!(parse_stdin_password("crlf-pass\r\n").unwrap(), "crlf-pass");
    assert_eq!(parse_stdin_password("no-newline").unwrap(), "no-newline");
    assert_eq!(
        parse_stdin_password("trailing-space \n").unwrap(),
        "trailing-space ",
        "a trailing space is part of the password and must be preserved"
    );
    assert_eq!(
        parse_stdin_password("a\nb\n").unwrap(),
        "a\nb",
        "only the final newline is stripped; interior newlines stay"
    );
}

// An empty or newline-only stdin line is rejected as invalid input, never
// accepted as an empty password.
#[test]
fn parse_stdin_password_rejects_empty_input() {
    for line in ["", "\n", "\r\n"] {
        let err = parse_stdin_password(line).unwrap_err();
        assert_eq!(
            err.code(),
            CliBoundaryCode::CliUserInputInvalid,
            "empty stdin line {line:?} must be rejected as invalid input"
        );
    }
}

// Lost-password recovery: `--require-existing` refuses a data dir with no database BEFORE anything is
// created, so a mistyped path cannot silently produce (and change) a new empty database. Exit class 2.
#[test]
fn require_existing_refuses_a_missing_database_and_creates_nothing() {
    let dir = std::env::temp_dir().join(format!("aionx-user-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let db_path = dir.join("aionui-backend.db");

    let err = check_target(&db_path, true).unwrap_err();
    assert_eq!(err.code(), CliBoundaryCode::CliUserDataDirNotFound);
    assert_eq!(err.exit_code(), ExitCode::from(2));
    assert!(!dir.exists(), "the refusal must not create the data dir");

    // Without the flag a fresh bootstrap is still allowed.
    check_target(&db_path, false).unwrap();
}

// The host holds the data-dir instance guard while it runs. The password change must refuse, change
// nothing, and work again once the host has stopped. Fails closed, exit class 2.
#[tokio::test]
async fn password_change_refuses_while_a_host_holds_the_data_dir() {
    let dir = std::env::temp_dir().join(format!("aionx-user-guard-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("aionui-backend.db");

    let host = aionui_db::DataDirInstanceGuard::try_acquire(&db_path)
        .unwrap()
        .expect("the first holder wins");
    let err = acquire_exclusive(&db_path).await.unwrap_err();
    assert_eq!(err.code(), CliBoundaryCode::CliUserHostRunning);
    assert_eq!(err.exit_code(), ExitCode::from(2));

    drop(host);
    let guard = acquire_exclusive(&db_path).await.unwrap();
    assert!(guard.is_some(), "free once the host is gone");
    // While this command holds it, a host starting now would be refused in turn.
    assert!(
        aionui_db::DataDirInstanceGuard::try_acquire(&db_path)
            .unwrap()
            .is_none()
    );
    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}

// A recovery run that names an unknown account is refused as a config-class error (exit 2), not
// reported as a success or an internal failure; the service itself writes nothing (aionui-auth tests).
#[test]
fn a_reset_naming_an_unknown_account_maps_to_user_not_found() {
    let err = map_account_error(AccountError::NotFound("bbo".into()));
    assert_eq!(err.code(), CliBoundaryCode::CliUserNotFound);
    assert_eq!(err.exit_code(), ExitCode::from(2));
}
