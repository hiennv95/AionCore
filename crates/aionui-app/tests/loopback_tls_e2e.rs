//! `--loopback-tls`: a real host process serving the desktop app over TLS on
//! 127.0.0.1 next to its HTTP listener, and publishing `<data-dir>/identity.json`.
//! The client pins the fingerprint from that file, as the desktop app does.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use aionui_peer::{Fingerprint, PeerIdentity, ServerPin, client_config};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

struct Host {
    child: Child,
    http_port: u16,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn(data_dir: &Path, port: u16, loopback_tls: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aioncore"));
    command
        .args(["--host", "127.0.0.1", "--port", &port.to_string(), "--data-dir"])
        .arg(data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if loopback_tls {
        command.arg("--loopback-tls");
    }
    command.spawn().unwrap()
}

async fn start_host(data_dir: &Path, loopback_tls: bool) -> Host {
    let http_port = free_port();
    let child = spawn(data_dir, http_port, loopback_tls);
    for _ in 0..300 {
        if let Ok((200, _)) = http("GET", http_port, "/api/auth/status", None).await {
            return Host { child, http_port };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("host did not answer on port {http_port}");
}

/// Plain HTTP/1.1 request; returns the status and the JSON body (Null when not JSON).
async fn http(method: &str, port: u16, path: &str, body: Option<&Value>) -> std::io::Result<(u16, Value)> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    exchange(stream, method, &format!("127.0.0.1:{port}"), path, body).await
}

async fn tls(
    pin: &str,
    port: u16,
    host_header: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::io::Result<(u16, Value)> {
    let scratch = tempfile::tempdir().unwrap();
    let client = PeerIdentity::load_or_create(scratch.path(), "test-client").unwrap();
    let config = client_config(&client, ServerPin::Expect(Fingerprint::parse(pin).unwrap())).unwrap();
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let stream = TlsConnector::from(Arc::clone(&config))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await?;
    exchange(stream, method, host_header, path, body).await
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    method: &str,
    host: &str,
    path: &str,
    body: Option<&Value>,
) -> std::io::Result<(u16, Value)> {
    // A bearer token rides in the path argument as `path|token` to keep call sites short.
    let (path, auth) = match path.split_once('|') {
        Some((path, token)) => (path, format!("Authorization: Bearer {token}\r\n")),
        None => (path, String::new()),
    };
    let payload = body.map(Value::to_string).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("no HTTP status in {text:?}")))?;
    let json = match (text.find('{'), text.rfind('}')) {
        (Some(start), Some(end)) if start < end => serde_json::from_str(&text[start..=end]).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    Ok((status, json))
}

fn metadata(data_dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(data_dir.join("identity.json")).unwrap()).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn wrong_pin(pin: &str) -> String {
    let first = if pin.starts_with('0') { '1' } else { '0' };
    format!("{first}{}", &pin[1..])
}

#[tokio::test]
async fn loopback_tls_serves_the_desktop_next_to_the_http_listener() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    let host = start_host(&data_dir, true).await;

    // Metadata names this process's two listeners and the host identity.
    let meta = metadata(&data_dir);
    let pin = meta["tls"]["fingerprint_sha256"].as_str().unwrap().to_owned();
    let tls_port = u16::try_from(meta["port"].as_u64().unwrap()).unwrap();
    assert_eq!(meta["version"], 1);
    assert_eq!(meta["http_port"], host.http_port);
    assert_ne!(tls_port, host.http_port, "two different listeners");
    assert_eq!(meta["tls"]["enabled"], true);
    assert_eq!(meta["host_id"], json!(pin));
    assert_eq!(pin.len(), 64);
    assert!(
        pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{pin}"
    );
    assert_eq!(mode(&data_dir.join("identity.json")), 0o600);
    assert_eq!(mode(&data_dir.join("peer").join("identity.key")), 0o600);

    // TLS with the published pin answers; the certificate it presents is that pin.
    let tls_host = format!("127.0.0.1:{tls_port}");
    let (status, _) = tls(&pin, tls_port, &tls_host, "GET", "/api/auth/status", None)
        .await
        .unwrap();
    assert_eq!(status, 200, "TLS listener");
    // Any other pin fails the handshake.
    assert!(
        tls(&wrong_pin(&pin), tls_port, &tls_host, "GET", "/api/auth/status", None)
            .await
            .is_err(),
        "a wrong pin must not connect"
    );
    // A DNS-rebound name is refused on the TLS listener too.
    let (status, _) = tls(
        &pin,
        tls_port,
        &format!("rebind.test:{tls_port}"),
        "GET",
        "/api/auth/status",
        None,
    )
    .await
    .unwrap();
    assert_ne!(status, 200, "foreign Host header");

    // The HTTP listener keeps serving, but no longer the desktop bootstrap.
    let (status, _) = http("GET", host.http_port, "/api/auth/status", None).await.unwrap();
    assert_eq!(status, 200, "HTTP listener");
    let secret = std::fs::read_to_string(data_dir.join("app-bootstrap.token")).unwrap();
    let session = json!({"bootstrap_token": secret.trim(), "device_name": "Mac"});
    let proof = json!({"nonce": "ab".repeat(16)});
    let (status, _) = http("POST", host.http_port, "/api/devices/app-session", Some(&session))
        .await
        .unwrap();
    assert_eq!(status, 404, "app-session over plain HTTP");
    let (status, _) = http("POST", host.http_port, "/api/devices/host-proof", Some(&proof))
        .await
        .unwrap();
    assert_eq!(status, 404, "host-proof over plain HTTP");

    // Over TLS the desktop app gets its proof and its session.
    let (status, body) = tls(
        &pin,
        tls_port,
        &tls_host,
        "POST",
        "/api/devices/host-proof",
        Some(&proof),
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "host-proof over TLS: {body}");
    let (status, body) = tls(
        &pin,
        tls_port,
        &tls_host,
        "POST",
        "/api/devices/app-session",
        Some(&session),
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "app-session over TLS: {body}");

    // That desktop session then works over TLS only.
    let access = body["data"]["access_token"].as_str().unwrap().to_owned();
    let (status, body) = tls(
        &pin,
        tls_port,
        &tls_host,
        "GET",
        &format!("/api/auth/user|{access}"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "desktop session over TLS: {body}");
    let (status, body) = http("GET", host.http_port, &format!("/api/auth/user|{access}"), None)
        .await
        .unwrap();
    assert_eq!(
        (status, body["code"].clone()),
        (403, json!("DESKTOP_REQUIRES_LOOPBACK_TLS")),
        "desktop session over plain HTTP: {body}"
    );
    drop(host);
}

#[tokio::test]
async fn the_identity_survives_a_restart_and_a_partial_one_stops_startup() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    let mut host = start_host(&data_dir, true).await;
    let first = metadata(&data_dir);
    host.child.kill().await.unwrap();

    let mut host = start_host(&data_dir, true).await;
    let second = metadata(&data_dir);
    assert_eq!(second["tls"]["fingerprint_sha256"], first["tls"]["fingerprint_sha256"]);
    assert_eq!(second["host_id"], first["host_id"]);
    assert_eq!(second["http_port"], host.http_port);
    let pin = second["tls"]["fingerprint_sha256"].as_str().unwrap().to_owned();
    let tls_port = u16::try_from(second["port"].as_u64().unwrap()).unwrap();
    let (status, _) = tls(
        &pin,
        tls_port,
        &format!("127.0.0.1:{tls_port}"),
        "GET",
        "/api/auth/status",
        None,
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "restarted TLS listener, same pin");
    host.child.kill().await.unwrap();

    // Key lost: startup fails instead of minting a new identity, and publishes nothing.
    let cert = std::fs::read(data_dir.join("peer").join("identity.crt")).unwrap();
    let published = std::fs::read(data_dir.join("identity.json")).unwrap();
    std::fs::remove_file(data_dir.join("peer").join("identity.key")).unwrap();
    let mut child = spawn(&data_dir, free_port(), true);
    let exit = tokio::time::timeout(Duration::from_secs(60), child.wait())
        .await
        .expect("host must stop on a partial identity")
        .unwrap();
    assert!(!exit.success());
    assert_eq!(std::fs::read(data_dir.join("peer").join("identity.crt")).unwrap(), cert);
    assert!(!data_dir.join("peer").join("identity.key").exists());
    assert_eq!(std::fs::read(data_dir.join("identity.json")).unwrap(), published);
}

/// Every loopback client shares 127.0.0.1: idle connections from other local processes
/// must not lock the desktop app out of the TLS listener.
#[tokio::test]
async fn idle_local_connections_do_not_lock_the_desktop_out() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    let _host = start_host(&data_dir, true).await;
    let meta = metadata(&data_dir);
    let pin = meta["tls"]["fingerprint_sha256"].as_str().unwrap().to_owned();
    let tls_port = u16::try_from(meta["port"].as_u64().unwrap()).unwrap();
    // More than the device listener's per-address limit (32), held open without a handshake.
    let mut idle = Vec::new();
    for _ in 0..40 {
        idle.push(TcpStream::connect(("127.0.0.1", tls_port)).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = tls(
        &pin,
        tls_port,
        &format!("127.0.0.1:{tls_port}"),
        "GET",
        "/api/auth/status",
        None,
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    drop(idle);
}

/// A key others can read is refused before it is loaded: the host does not start, the
/// key is left as it is, and nothing is published for it.
#[tokio::test]
async fn an_exposed_key_stops_startup_without_publishing() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    let mut host = start_host(&data_dir, true).await;
    host.child.kill().await.unwrap();
    let key = data_dir.join("peer").join("identity.key");
    let published = std::fs::read(data_dir.join("identity.json")).unwrap();
    let before = std::fs::read(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut child = spawn(&data_dir, free_port(), true);
    let exit = tokio::time::timeout(Duration::from_secs(60), child.wait())
        .await
        .expect("host must stop on an exposed key")
        .unwrap();
    assert!(!exit.success());
    assert_eq!(std::fs::read(&key).unwrap(), before);
    assert_eq!(mode(&key), 0o644, "not chmodded");
    assert_eq!(std::fs::read(data_dir.join("identity.json")).unwrap(), published);
}

#[tokio::test]
async fn a_planted_link_is_replaced_without_touching_its_target() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let victim = scratch.path().join("victim.json");
    std::fs::write(&victim, b"keep me").unwrap();
    std::os::unix::fs::symlink(&victim, data_dir.join("identity.json")).unwrap();

    let host = start_host(&data_dir, true).await;
    let link = std::fs::symlink_metadata(data_dir.join("identity.json")).unwrap();
    assert!(link.file_type().is_file(), "the link itself was replaced");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
    assert_eq!(metadata(&data_dir)["http_port"], host.http_port);
}

#[tokio::test]
async fn without_the_flag_nothing_changes() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    // An earlier start with the flag left its metadata behind.
    let mut host = start_host(&data_dir, true).await;
    host.child.kill().await.unwrap();
    assert!(data_dir.join("identity.json").exists());

    let host = start_host(&data_dir, false).await;
    assert!(
        std::fs::symlink_metadata(data_dir.join("identity.json")).is_err(),
        "stale metadata removed"
    );
    let secret = std::fs::read_to_string(data_dir.join("app-bootstrap.token")).unwrap();
    let session = json!({"bootstrap_token": secret.trim(), "device_name": "Mac"});
    let (status, body) = http("POST", host.http_port, "/api/devices/app-session", Some(&session))
        .await
        .unwrap();
    assert_eq!(status, 200, "plain HTTP bootstrap without --loopback-tls: {body}");
}
