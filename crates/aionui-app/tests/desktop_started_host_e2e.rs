//! A host started with the arguments the desktop app uses (`DesktopLauncher`
//! in aionx/app): loopback bind, its own origin allowlist, a data dir it
//! creates itself. Audit run-2 SEC-D: such a host must match the launchd
//! host's browser and file posture.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::process::{Child, Command};

struct Host {
    _child: Child,
    base: String,
    port: u16,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_host(data_dir: &Path) -> Host {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_aioncore"))
        .args(["--host", "127.0.0.1", "--port", &port.to_string(), "--data-dir"])
        .arg(data_dir)
        // Keep in sync with DesktopLauncher.ensureHost (aionx/app/lib/src/host/desktop_launcher.dart).
        .args(["--allowed-origin", &format!("http://127.0.0.1:{port}")])
        .args(["--allowed-origin", &format!("http://localhost:{port}")])
        .args([
            "--strict-refresh",
            "--ws-token-expiry",
            "--access-token-ttl-secs",
            "900",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    for _ in 0..300 {
        if let Ok(resp) = client.get(format!("{base}/api/auth/status")).send().await
            && resp.status() == StatusCode::OK
        {
            return Host {
                _child: child,
                base,
                port,
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("host did not answer on {base}");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn desktop_started_host_matches_the_launchd_posture() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("host-data");
    let host = start_host(&data_dir).await;
    let client = reqwest::Client::new();
    let status = format!("{}/api/auth/status", host.base);

    // (1) Browser origin: only this host's own loopback origin may call it.
    let other_port = client
        .get(&status)
        .header("origin", "http://127.0.0.1:9")
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_port.status(),
        StatusCode::FORBIDDEN,
        "page on another loopback port"
    );
    let rebound = client
        .get(&status)
        .header("origin", "http://rebind.test:9")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::FORBIDDEN, "DNS-rebound page");
    let own = format!("http://127.0.0.1:{}", host.port);
    let same = client.get(&status).header("origin", own).send().await.unwrap();
    assert_eq!(same.status(), StatusCode::OK, "the host's own web client");
    let native = client.get(&status).send().await.unwrap();
    assert_eq!(native.status(), StatusCode::OK, "native client without Origin");

    // (2) Owner-only data dir and database (they hold the JWT signing secret).
    assert_eq!(mode(&data_dir), 0o700, "data dir");
    let db = data_dir.join("aionui-backend.db");
    assert_eq!(mode(&db) & 0o077, 0, "database file");

    // (3) Failed bootstrap attempts on loopback do not lock the desktop app out.
    let app_session = format!("{}/api/devices/app-session", host.base);
    for _ in 0..6 {
        let resp = client
            .post(&app_session)
            .json(&json!({"bootstrap_token": "wrong", "device_name": "x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let secret = std::fs::read_to_string(data_dir.join("app-bootstrap.token")).unwrap();
    let resp = client
        .post(&app_session)
        .json(&json!({"bootstrap_token": secret.trim(), "device_name": "Mac"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the real desktop app still gets its session"
    );
}
