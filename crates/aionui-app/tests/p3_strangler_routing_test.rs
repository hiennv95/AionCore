mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use common::build_app;
use tower::ServiceExt;

fn temp_svelte_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<html>svelte-root</html>").unwrap();
    std::fs::create_dir(dir.path().join("_app")).unwrap();
    std::fs::write(dir.path().join("_app/entry.js"), "console.log('svelte')").unwrap();
    dir
}

fn temp_legacy_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<html>legacy-react</html>").unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/index.js"), "console.log('react')").unwrap();
    dir
}

async fn get_response(router: axum::Router, req: Request<Body>) -> (StatusCode, String, axum::response::Response) {
    let response = router.oneshot(req).await.unwrap();
    let status = response.status();
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        axum::response::Response::from_parts(parts, Body::empty()),
    )
}

#[tokio::test]
async fn p3_strangler_dual_routing_matrix() {
    let svelte = temp_svelte_dir();
    let legacy = temp_legacy_dir();

    // Symlink escape setup
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("host_secret.txt"), "HOST_SECRET_DATA").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        outside.path().join("host_secret.txt"),
        legacy.path().join("assets/symlink_outside.txt"),
    )
    .unwrap();

    let (base_router, _services) = build_app().await;
    let app = aionui_app::with_static_web_clients(base_router, Some(svelte.path()), Some(legacy.path()));

    // 1. /legacy → 308 to /legacy/ (with Location header and preserved query)
    let (status, _, res) = get_response(
        app.clone(),
        Request::builder().uri("/legacy").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/legacy/");

    let (status, _, res) = get_response(
        app.clone(),
        Request::builder().uri("/legacy?param=val").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/legacy/?param=val");

    // 2. /legacy/ and deep path serve legacy index.html
    let (status, body, res) = get_response(
        app.clone(),
        Request::builder().uri("/legacy/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>legacy-react</html>");
    assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");

    let (status, body, _) = get_response(
        app.clone(),
        Request::builder()
            .uri("/legacy/conversation/abc-123")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>legacy-react</html>");

    // 3. /legacy/assets/<file> is served
    let (status, body, res) = get_response(
        app.clone(),
        Request::builder()
            .uri("/legacy/assets/index.js")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "console.log('react')");
    assert_eq!(res.headers().get("x-content-type-options").unwrap(), "nosniff");

    // 4. / still serves Svelte
    let (status, body, res) = get_response(app.clone(), Request::builder().uri("/").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>svelte-root</html>");
    assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");

    let (status, body, _) = get_response(
        app.clone(),
        Request::builder()
            .uri("/conversation/abc-123")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>svelte-root</html>");

    let (status, body, _) = get_response(
        app.clone(),
        Request::builder().uri("/_app/entry.js").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "console.log('svelte')");

    // 5. unknown /api/x → 404 (does not fall through to either SPA)
    let (status, body, _) = get_response(
        app.clone(),
        Request::builder()
            .uri("/api/x_nonexistent_endpoint")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("svelte-root") && !body.contains("legacy-react"));

    // 6. POST /legacy/ → 405 Method Not Allowed
    let (status, _, _) = get_response(
        app.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/legacy/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    // 7. Dotfiles and encoded traversal fail closed (404)
    std::fs::write(legacy.path().join(".env"), "SECRET_LEGACY").unwrap();
    let (status, body, _) = get_response(
        app.clone(),
        Request::builder().uri("/legacy/.env").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("SECRET_LEGACY"));

    let (status, _, _) = get_response(
        app.clone(),
        Request::builder().uri("/legacy/%2e%2e/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 8. Symlink escape fails closed (404)
    #[cfg(unix)]
    {
        let (status, body, _) = get_response(
            app.clone(),
            Request::builder()
                .uri("/legacy/assets/symlink_outside.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("HOST_SECRET_DATA"));
    }
}

#[tokio::test]
async fn p3_missing_index_html_fails_validation() {
    let empty_dir = tempfile::tempdir().unwrap();
    assert!(aionui_app::validate_static_dir(empty_dir.path()).is_err());
}

#[tokio::test]
async fn p3_omitted_legacy_flag_preserves_legacy_passthrough() {
    let svelte = temp_svelte_dir();
    let (base_router, _services) = build_app().await;

    // When legacy_dir is None (no --legacy-static-dir flag), /legacy/ is handled by root SPA
    let app = aionui_app::with_static_web_clients(base_router, Some(svelte.path()), None);

    let (status, body, _) = get_response(app, Request::builder().uri("/legacy/").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>svelte-root</html>");
}

#[tokio::test]
async fn p3_device_listener_router_includes_legacy_when_configured() {
    let svelte = temp_svelte_dir();
    let legacy = temp_legacy_dir();
    let (base_router, _services) = build_app().await;

    // Configured with legacy
    let router_with =
        aionui_app::with_static_web_clients(base_router.clone(), Some(svelte.path()), Some(legacy.path()));
    let (status, body, _) = get_response(
        router_with,
        Request::builder().uri("/legacy/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>legacy-react</html>");

    // Configured without legacy
    let router_without = aionui_app::with_static_web_clients(base_router, Some(svelte.path()), None);
    let (status, body, _) = get_response(
        router_without,
        Request::builder().uri("/legacy/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>svelte-root</html>");
}
