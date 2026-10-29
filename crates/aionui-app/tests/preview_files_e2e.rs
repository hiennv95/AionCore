//! Preview v1 (ADR-017) through the real app router: host-minted file refs, read-time
//! re-validation, preview kinds and caps, and who may read (desktop, paired devices when the
//! owner allows it, never the agent helper). Refs are minted through `PreviewService::mint`
//! directly: wiring agent reports into minting needs real agent captures (not in this slice).

mod common;

use std::path::Path;
use std::sync::Arc;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use aionui_db::{SqliteConversationRepository, SqlitePreviewRepository};
use aionui_preview::PreviewService;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, json_with_token, setup_and_login};

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

struct Host {
    app: axum::Router,
    services: aionui_app::AppServices,
    preview: PreviewService,
    owner: String,
    desktop: String,
    device: String,
    device_id: String,
    _data: tempfile::TempDir,
    workspace: tempfile::TempDir,
    outside: tempfile::TempDir,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

fn public_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

impl Host {
    async fn send(&self, req: Request<Body>) -> Reply {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Reply { status, headers, body }
    }

    async fn conversation(&self, id: &str, workspace: &Path) {
        sqlx::query(
            "INSERT INTO conversations (id, user_id, name, type, extra, created_at, updated_at) \
             VALUES (?, ?, 'c', 'acp', ?, 1, 1)",
        )
        .bind(id)
        .bind(&self.owner)
        .bind(json!({ "workspace": workspace.to_string_lossy() }).to_string())
        .execute(self.services.database.pool())
        .await
        .unwrap();
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = self.workspace.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    async fn mint(&self, conversation: &str, reported: &str) -> Option<String> {
        self.preview
            .mint(&self.owner, conversation, reported, Some("call-1"))
            .await
            .unwrap()
            .map(|r| r.id)
    }

    async fn files(&self, conversation: &str, token: &str) -> Reply {
        self.send(get(&format!("/api/conversations/{conversation}/files"), token))
            .await
    }

    async fn content(&self, conversation: &str, file: &str, token: &str) -> Reply {
        self.send(get(
            &format!("/api/conversations/{conversation}/files/{file}/content"),
            token,
        ))
        .await
    }

    async fn diff(&self, conversation: &str, file: &str, token: &str) -> Reply {
        self.send(get(
            &format!("/api/conversations/{conversation}/files/{file}/diff"),
            token,
        ))
        .await
    }

    fn git(&self, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(self.workspace.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}");
    }
}

async fn host() -> Host {
    let data = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(data.path()).await;
    let bootstrap = std::fs::read_to_string(data.path().join("app-bootstrap.token")).unwrap();
    let pool = services.database.pool().clone();
    let preview = PreviewService::new(
        Arc::new(SqlitePreviewRepository::new(pool.clone())),
        Arc::new(SqliteConversationRepository::new(pool)),
    );
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let mut host = Host {
        app,
        services,
        preview,
        owner,
        desktop: String::new(),
        device: String::new(),
        device_id: String::new(),
        _data: data,
        workspace: tempfile::tempdir().unwrap(),
        outside: tempfile::tempdir().unwrap(),
    };
    let desktop = host
        .send(public_post(
            "/api/devices/app-session",
            json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
        ))
        .await
        .json();
    host.desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();
    let pairing = host
        .send(json_with_token(
            "POST",
            "/api/devices/pairings",
            json!({}),
            &host.desktop,
            "c",
        ))
        .await
        .json();
    let paired = host
        .send(public_post(
            "/api/devices/pair",
            json!({"secret": pairing["data"]["secret"], "device_name": "Phone", "device_kind": "mobile"}),
        ))
        .await
        .json();
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap().to_owned();
    host.send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &host.desktop,
        "c",
    ))
    .await;
    let claimed = host
        .send(public_post(
            "/api/devices/pair/claim",
            json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
        ))
        .await
        .json();
    host.device = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();
    host.device_id = claimed["data"]["session"]["device_id"].as_str().unwrap().to_owned();
    host.conversation("conv-a", host.workspace.path()).await;
    host
}

#[tokio::test]
async fn the_owner_lists_and_reads_minted_files_with_host_decided_kinds() {
    let h = host().await;
    h.write("notes.txt", b"hello");
    h.write("docs/README.md", b"# Title");
    h.write("logo.png", PNG);
    h.write("page.html", b"<script>alert(1)</script>");
    h.write("pic.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>");
    h.write("data.bin", &[0xff, 0xfe, 0x00, 0x01]);

    let txt = h.mint("conv-a", "notes.txt").await.expect("relative path mints");
    let abs = h.workspace.path().join("docs/README.md");
    h.mint("conv-a", abs.to_str().unwrap())
        .await
        .expect("absolute path inside mints");
    h.mint("conv-a", "logo.png").await.unwrap();
    let html = h.mint("conv-a", "page.html").await.unwrap();
    let svg = h.mint("conv-a", "pic.svg").await.unwrap();
    let bin = h.mint("conv-a", "data.bin").await.unwrap();

    let list = h.files("conv-a", &h.desktop).await;
    assert_eq!(list.status, StatusCode::OK);
    let items = list.json()["data"].as_array().unwrap().clone();
    let kind = |rel: &str| {
        items
            .iter()
            .find(|f| f["rel_path"] == rel)
            .map(|f| f["preview_kind"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(items.len(), 6);
    assert_eq!(kind("notes.txt"), "text");
    assert_eq!(kind("docs/README.md"), "markdown");
    assert_eq!(kind("logo.png"), "image");
    assert_eq!(kind("page.html"), "text", "HTML is shown as source");
    assert_eq!(kind("pic.svg"), "image");
    assert_eq!(kind("data.bin"), "unsupported");
    let text = list.json().to_string();
    assert!(
        !text.contains(h.workspace.path().to_str().unwrap()),
        "no host path in the list"
    );

    let r = h.content("conv-a", &txt, &h.desktop).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, b"hello");
    assert_eq!(r.headers["content-type"], "text/plain; charset=utf-8");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert!(
        r.headers["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );

    let r = h.content("conv-a", &html, &h.desktop).await;
    assert_eq!(
        r.headers["content-type"], "text/plain; charset=utf-8",
        "never text/html"
    );

    let r = h.content("conv-a", &svg, &h.desktop).await;
    assert_eq!(r.headers["content-type"], "image/svg+xml");
    let csp = r.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("sandbox"), "{csp}");

    let r = h.content("conv-a", &bin, &h.desktop).await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(r.json()["code"], "PREVIEW_UNSUPPORTED");
}

#[tokio::test]
async fn minting_refuses_anything_that_is_not_a_regular_file_inside_the_workspace() {
    let h = host().await;
    let secret = h.outside.path().join("secret.txt");
    std::fs::write(&secret, b"outside").unwrap();
    h.write("sub/ok.txt", b"ok");
    std::os::unix::fs::symlink(&secret, h.workspace.path().join("link.txt")).unwrap();

    for reported in [
        secret.to_str().unwrap().to_owned(),
        "../secret.txt".to_owned(),
        format!(
            "sub/../../{}/secret.txt",
            h.outside.path().file_name().unwrap().to_string_lossy()
        ),
        "link.txt".to_owned(),
        "sub".to_owned(),
        "missing.txt".to_owned(),
        String::new(),
    ] {
        assert_eq!(h.mint("conv-a", &reported).await, None, "{reported:?} must not mint");
    }
    // A conversation of another user, or one that does not exist, mints nothing.
    assert!(
        h.preview
            .mint("someone-else", "conv-a", "sub/ok.txt", None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(h.mint("conv-missing", "sub/ok.txt").await, None);
    assert!(
        h.files("conv-a", &h.desktop).await.json()["data"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn reads_re_validate_the_file_and_the_workspace() {
    let h = host().await;
    let path = h.write("a.txt", b"first");
    let id = h.mint("conv-a", "a.txt").await.unwrap();

    // Rewritten in place: still inside, served, marked stale.
    std::fs::write(&path, b"second, longer").unwrap();
    let mtime = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let list = h.files("conv-a", &h.desktop).await.json();
    assert_eq!(list["data"][0]["stale"], true);
    assert_eq!(h.content("conv-a", &id, &h.desktop).await.body, b"second, longer");

    // Swapped for a symlink to a file outside the workspace: not served, path-free 404.
    let secret = h.outside.path().join("secret.txt");
    std::fs::write(&secret, b"outside").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&secret, &path).unwrap();
    let r = h.content("conv-a", &id, &h.desktop).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.json()["code"], "FILE_NOT_FOUND");
    assert!(!String::from_utf8_lossy(&r.body).contains("outside"));
    assert!(!String::from_utf8_lossy(&r.body).contains(h.outside.path().to_str().unwrap()));

    // Removed: 404 and stale.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(h.content("conv-a", &id, &h.desktop).await.status, StatusCode::NOT_FOUND);

    // The conversation's workspace changed: every old ref is dead.
    let p2 = h.write("b.txt", b"b");
    let id2 = h.mint("conv-a", "b.txt").await.unwrap();
    let other = tempfile::tempdir().unwrap();
    std::fs::write(other.path().join("b.txt"), b"elsewhere").unwrap();
    sqlx::query("UPDATE conversations SET extra = ? WHERE id = 'conv-a'")
        .bind(json!({ "workspace": other.path().to_string_lossy() }).to_string())
        .execute(h.services.database.pool())
        .await
        .unwrap();
    assert_eq!(
        h.content("conv-a", &id2, &h.desktop).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(p2.exists());
}

#[tokio::test]
async fn files_over_the_preview_cap_are_listed_but_not_served() {
    let h = host().await;
    h.write("big.txt", &vec![b'a'; 1024 * 1024 + 1]);
    let mut png = PNG.to_vec();
    png.resize(20 * 1024 * 1024 + 1, 0);
    h.write("big.png", &png);
    let text = h.mint("conv-a", "big.txt").await.unwrap();
    let image = h.mint("conv-a", "big.png").await.unwrap();

    let list = h.files("conv-a", &h.desktop).await.json();
    assert!(list["data"].as_array().unwrap().iter().all(|f| f["too_large"] == true));
    for id in [text, image] {
        let r = h.content("conv-a", &id, &h.desktop).await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(r.json()["code"], "PREVIEW_TOO_LARGE");
    }
}

#[tokio::test]
async fn an_image_extension_without_image_bytes_is_unsupported() {
    let h = host().await;
    h.write("fake.png", b"<svg onload=alert(1)>");
    let id = h.mint("conv-a", "fake.png").await.unwrap();
    let list = h.files("conv-a", &h.desktop).await.json();
    assert_eq!(list["data"][0]["preview_kind"], "unsupported");
    assert_eq!(
        h.content("conv-a", &id, &h.desktop).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[tokio::test]
async fn who_may_read_previews() {
    let h = host().await;
    h.write("a.txt", b"hello");
    let id = h.mint("conv-a", "a.txt").await.unwrap();

    // The agent helper never reads previews.
    common::ensure_conversation(&h.services, h.owner.as_str(), "conv-a").await;
    let issue = h.services.runtime_token_service.issue(
        h.owner.as_str(),
        "conv-a",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    for uri in [
        "/api/conversations/conv-a/files".to_owned(),
        format!("/api/conversations/conv-a/files/{id}/content"),
    ] {
        let r = h
            .send(
                Request::builder()
                    .uri(&uri)
                    .header("x-aionui-runtime-token", issue.token.as_str())
                    .header("x-aionui-user-id", h.owner.as_str())
                    .header("x-aionui-conversation-id", "conv-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            (r.status, r.json()["code"].clone()),
            (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY")),
            "{uri}"
        );
    }

    // A paired phone: refused while the owner setting is off (the default).
    let r = h.files("conv-a", &h.device).await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::FORBIDDEN, json!("PREVIEW_DEVICES_DISABLED"))
    );
    assert_eq!(h.content("conv-a", &id, &h.device).await.status, StatusCode::FORBIDDEN);

    // Only the desktop app reads and changes the setting.
    let r = h.send(get("/api/devices/file-preview", &h.desktop)).await;
    assert_eq!(r.json()["data"], json!({"devices_allowed": false}));
    let r = h
        .send(json_with_token(
            "PUT",
            "/api/devices/file-preview",
            json!({"devices_allowed": true}),
            &h.device,
            "c",
        ))
        .await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY"))
    );
    let r = h
        .send(json_with_token(
            "PUT",
            "/api/devices/file-preview",
            json!({"devices_allowed": true}),
            &h.desktop,
            "c",
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));

    // With the setting on, the phone reads.
    assert_eq!(h.files("conv-a", &h.device).await.status, StatusCode::OK);
    assert_eq!(h.content("conv-a", &id, &h.device).await.body, b"hello");

    // Another user sees nothing; refs never cross conversations; unknown ids are path-free 404s.
    let (mut app, services) = (h.app.clone(), &h.services);
    let (bob, _) = setup_and_login(&mut app, services, "bob", "StrongP@ss2").await;
    // Jev 053: bob's password session is device-less, so his own (off) device setting
    // refuses him before any lookup of the owner's conversation.
    let refused = (StatusCode::FORBIDDEN, json!("PREVIEW_DEVICES_DISABLED"));
    let r = h.files("conv-a", &bob).await;
    assert_eq!((r.status, r.json()["code"].clone()), refused);
    let r = h.content("conv-a", &id, &bob).await;
    assert_eq!((r.status, r.json()["code"].clone()), refused);
    h.conversation("conv-b", h.workspace.path()).await;
    assert_eq!(h.content("conv-b", &id, &h.desktop).await.status, StatusCode::NOT_FOUND);
    let r = h.content("conv-a", "pf_missing", &h.desktop).await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::NOT_FOUND, json!("FILE_NOT_FOUND"))
    );

    // A revoked phone is out (auth middleware).
    let r = h
        .send(json_with_token(
            "POST",
            &format!("/api/devices/{}/revoke", h.device_id),
            json!({}),
            &h.desktop,
            "c",
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(h.files("conv-a", &h.device).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replaced_files_unreadable_files_and_swapped_folders() {
    let h = host().await;

    // Replaced by a new file through a rename: still the regular file at that path, so served and stale.
    let path = h.write("r.txt", b"old");
    let id = h.mint("conv-a", "r.txt").await.unwrap();
    let tmp = h.write("r.tmp", b"new content");
    std::fs::rename(&tmp, &path).unwrap();
    assert_eq!(h.content("conv-a", &id, &h.desktop).await.body, b"new content");
    let list = h.files("conv-a", &h.desktop).await.json();
    let row = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["stale"], true);

    // A parent folder swapped for a symlink to outside: path-free 404.
    h.write("dir/in.txt", b"inside");
    let in_dir = h.mint("conv-a", "dir/in.txt").await.unwrap();
    std::fs::write(h.outside.path().join("in.txt"), b"outside").unwrap();
    std::fs::remove_dir_all(h.workspace.path().join("dir")).unwrap();
    std::os::unix::fs::symlink(h.outside.path(), h.workspace.path().join("dir")).unwrap();
    let r = h.content("conv-a", &in_dir, &h.desktop).await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::NOT_FOUND, json!("FILE_NOT_FOUND"))
    );

    // A file the host cannot open: path-free 404, nothing leaks.
    use std::os::unix::fs::PermissionsExt;
    let locked = h.write("locked.txt", b"secret");
    let locked_id = h.mint("conv-a", "locked.txt").await.unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = h.content("conv-a", &locked_id, &h.desktop).await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::NOT_FOUND, json!("FILE_NOT_FOUND"))
    );
    assert!(!String::from_utf8_lossy(&r.body).contains(h.workspace.path().to_str().unwrap()));
}

#[tokio::test]
async fn the_routes_need_a_session_and_the_setting_needs_csrf() {
    let h = host().await;
    let r = h
        .send(
            Request::builder()
                .uri("/api/conversations/conv-a/files")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = h
        .send(
            Request::builder()
                .uri("/api/devices/file-preview")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let no_csrf = Request::builder()
        .method("PUT")
        .uri("/api/devices/file-preview")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", h.desktop))
        .body(Body::from(json!({"devices_allowed": true}).to_string()))
        .unwrap();
    assert_eq!(h.send(no_csrf).await.status, StatusCode::FORBIDDEN);
    let r = h.send(get("/api/devices/file-preview", &h.desktop)).await;
    assert_eq!(
        r.json()["data"]["devices_allowed"],
        false,
        "refused PUT changed nothing"
    );

    let r = h
        .send(json_with_token(
            "PUT",
            "/api/devices/file-preview",
            json!({"devices_allowed": true, "x": 1}),
            &h.desktop,
            "c",
        ))
        .await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("BAD_REQUEST"))
    );
}

const PDF: &[u8] = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n";

#[tokio::test]
async fn pdf_needs_magic_and_extension_and_is_served_as_an_attachment() {
    let h = host().await;
    h.write("doc.pdf", PDF);
    h.write("fake.pdf", b"<html>not a pdf</html>");
    h.write("doc.bin", PDF);
    let mut big = PDF.to_vec();
    big.resize(20 * 1024 * 1024 + 1, b' ');
    h.write("big.pdf", &big);
    let pdf = h.mint("conv-a", "doc.pdf").await.unwrap();
    let fake = h.mint("conv-a", "fake.pdf").await.unwrap();
    let bin = h.mint("conv-a", "doc.bin").await.unwrap();
    let large = h.mint("conv-a", "big.pdf").await.unwrap();

    let list = h.files("conv-a", &h.desktop).await.json();
    let kind = |rel: &str| {
        list["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rel_path"] == rel)
            .map(|f| (f["preview_kind"].clone(), f["too_large"].clone()))
            .unwrap()
    };
    assert_eq!(kind("doc.pdf"), (json!("pdf"), json!(false)));
    assert_eq!(kind("fake.pdf"), (json!("unsupported"), json!(false)));
    assert_eq!(kind("doc.bin"), (json!("unsupported"), json!(false)));
    assert_eq!(kind("big.pdf"), (json!("pdf"), json!(true)));

    let r = h.content("conv-a", &pdf, &h.desktop).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, PDF);
    assert_eq!(r.headers["content-type"], "application/pdf");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(r.headers["content-disposition"], "attachment");
    assert_eq!(r.headers["content-security-policy"], "default-src 'none'; sandbox");
    for id in [&fake, &bin] {
        let r = h.content("conv-a", id, &h.desktop).await;
        assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let r = h.content("conv-a", &large, &h.desktop).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn diff_is_head_against_disk_with_relative_headers() {
    let h = host().await;
    h.git(&["init", "-q"]);
    h.write("src/a.txt", b"one\n");
    h.git(&["add", "-A"]);
    h.git(&["commit", "-qm", "c"]);
    h.write("src/a.txt", b"two\n");
    h.write("new.md", b"# new\n");
    h.write("logo.png", PNG);
    let tracked = h.mint("conv-a", "src/a.txt").await.unwrap();
    let untracked = h.mint("conv-a", "new.md").await.unwrap();
    let image = h.mint("conv-a", "logo.png").await.unwrap();

    let r = h.diff("conv-a", &tracked, &h.desktop).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let d = &r.json()["data"];
    assert_eq!(
        (d["source"].clone(), d["status"].clone()),
        (json!("head_vs_disk"), json!("ok"))
    );
    assert_eq!(
        (d["base"].clone(), d["truncated"].clone()),
        (json!("head"), json!(false))
    );
    let text = d["diff"].as_str().unwrap();
    assert!(
        text.contains("--- a/src/a.txt\n+++ b/src/a.txt\n") && text.contains("-one\n+two\n"),
        "{text}"
    );
    let body = String::from_utf8_lossy(&r.body).to_string();
    let ws = std::fs::canonicalize(h.workspace.path()).unwrap();
    assert!(!body.contains(ws.to_str().unwrap()) && !body.contains(h.workspace.path().to_str().unwrap()));

    let d = h.diff("conv-a", &untracked, &h.desktop).await.json()["data"].clone();
    assert_eq!(d["base"], "absent");
    let text = d["diff"].as_str().unwrap();
    assert!(
        text.contains("--- /dev/null\n+++ b/new.md\n") && text.contains("\n+# new\n"),
        "{text}"
    );

    let r = h.diff("conv-a", &image, &h.desktop).await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, json!("PREVIEW_UNSUPPORTED"))
    );
    let r = h.diff("conv-a", "pf_missing", &h.desktop).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn diff_outside_a_repo_is_not_a_repo() {
    let h = host().await;
    h.write("a.txt", b"x\n");
    let id = h.mint("conv-a", "a.txt").await.unwrap();
    let r = h.diff("conv-a", &id, &h.desktop).await;
    assert_eq!(r.status, StatusCode::OK);
    let d = &r.json()["data"];
    assert_eq!(
        (d["status"].clone(), d["base"].clone(), d["diff"].clone()),
        (json!("not_a_repo"), Value::Null, json!(""))
    );
}

#[tokio::test]
async fn pdf_content_and_diff_keep_the_reader_gates() {
    let h = host().await;
    h.git(&["init", "-q"]);
    h.write("a.txt", b"hello\n");
    h.write("doc.pdf", PDF);
    let text = h.mint("conv-a", "a.txt").await.unwrap();
    let pdf = h.mint("conv-a", "doc.pdf").await.unwrap();
    let uris = [
        format!("/api/conversations/conv-a/files/{pdf}/content"),
        format!("/api/conversations/conv-a/files/{text}/diff"),
    ];

    common::ensure_conversation(&h.services, h.owner.as_str(), "conv-a").await;
    let issue = h.services.runtime_token_service.issue(
        h.owner.as_str(),
        "conv-a",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let (mut app, services) = (h.app.clone(), &h.services);
    let (bob, _) = setup_and_login(&mut app, services, "bob", "StrongP@ss2").await;
    let disabled = (StatusCode::FORBIDDEN, json!("PREVIEW_DEVICES_DISABLED"));
    for uri in &uris {
        let r = h
            .send(
                Request::builder()
                    .uri(uri)
                    .header("x-aionui-runtime-token", issue.token.as_str())
                    .header("x-aionui-user-id", h.owner.as_str())
                    .header("x-aionui-conversation-id", "conv-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            (r.status, r.json()["code"].clone()),
            (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY")),
            "{uri}"
        );
        let r = h.send(get(uri, &h.device)).await;
        assert_eq!(
            (r.status, r.json()["code"].clone()),
            disabled,
            "paired device, setting off: {uri}"
        );
        let r = h.send(get(uri, &bob)).await;
        assert_eq!((r.status, r.json()["code"].clone()), disabled, "device-less: {uri}");
        assert_eq!(h.send(get(uri, &h.desktop)).await.status, StatusCode::OK, "{uri}");
    }
    h.send(json_with_token(
        "PUT",
        "/api/devices/file-preview",
        json!({"devices_allowed": true}),
        &h.desktop,
        "c",
    ))
    .await;
    for uri in &uris {
        assert_eq!(h.send(get(uri, &h.device)).await.status, StatusCode::OK, "{uri}");
    }
}
