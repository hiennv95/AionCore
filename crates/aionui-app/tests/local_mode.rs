use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn test_local_mode_skips_auth() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        local: true,
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();

    let router = aionui_app::create_router(&services).await.expect("build router");

    // Health check should work
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // An authenticated endpoint should work WITHOUT a token in local mode
    let response = router
        .oneshot(Request::builder().uri("/api/settings").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);

    services.database.close().await;
}

#[tokio::test]
async fn test_non_local_mode_requires_auth() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let services = aionui_app::AppServices::from_config(db, &aionui_app::AppConfig::default())
        .await
        .unwrap();

    let router = aionui_app::create_router(&services).await.expect("build router");

    let response = router
        .oneshot(Request::builder().uri("/api/settings").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "UNAUTHORIZED");

    services.database.close().await;
}

#[tokio::test]
async fn test_local_mode_aionpro_requires_session_and_allows_bootstrap_provision_without_csrf() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        identity_mode: aionui_app::IdentityMode::AionPro,
        bootstrap_secret: Some("bootstrap-secret".to_string()),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();
    let router = aionui_app::create_router(&services).await.expect("build router");

    let business_response = router
        .clone()
        .oneshot(Request::builder().uri("/api/settings").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(business_response.status(), StatusCode::UNAUTHORIZED);

    let provision_response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/auth/internal/external-users/pro-app")
                .header("content-type", "application/json")
                .header("x-aioncore-bootstrap-secret", "bootstrap-secret")
                .body(Body::from(r#"{"user_type":"aionpro","username":"Pro App User"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(provision_response.status(), StatusCode::OK);
    let body = to_bytes(provision_response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["user_type"], "aionpro");
    assert_ne!(json["data"]["user_id"], "system_default_user");

    services.database.close().await;
}

#[tokio::test]
async fn test_local_mode_never_serves_the_device_listener() {
    let dir = tempfile::tempdir().unwrap();
    // A listener left enabled by an earlier non-local launch must stay off.
    std::fs::create_dir_all(dir.path().join("devices")).unwrap();
    std::fs::write(
        dir.path().join("devices").join("listener.json"),
        r#"{"enabled":true,"port":0}"#,
    )
    .unwrap();
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        local: true,
        data_dir: dir.path().to_path_buf(),
        work_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();
    let router = aionui_app::create_router(&services).await.expect("build router");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/devices/listener")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INVALID_REQUEST");

    services.database.close().await;
}

#[tokio::test]
async fn test_local_mode_refuses_pages_from_other_sites() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        local: true,
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();
    let router = aionui_app::create_router(&services).await.expect("build router");
    let get = |origin: Option<&str>| {
        let mut request = Request::builder().uri("/api/settings");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        router.clone().oneshot(request.body(Body::empty()).unwrap())
    };

    // No auth in local mode, so another site's page must not get in (null too:
    // sandboxed iframes send it).
    for origin in ["https://evil.example", "null"] {
        assert_eq!(
            get(Some(origin)).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "{origin}"
        );
    }
    assert_ne!(
        get(Some("http://localhost:5173")).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_ne!(get(None).await.unwrap().status(), StatusCode::FORBIDDEN);

    services.database.close().await;
}
