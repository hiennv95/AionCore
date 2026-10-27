//! ADR-013 for extensions. Installing, updating, uninstalling, enabling or disabling an
//! extension puts code on the host or runs its lifecycle hooks, so a paired phone or
//! browser (and the agent helper) gets 403 `FS_OWNER_ONLY`. Listing stays open.

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, desktop_and_phone, get_with_token, json_with_token};

#[tokio::test]
async fn a_phone_cannot_install_or_switch_extensions_but_can_list_them() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, _services, _) = build_app_with_skill_paths(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let refused = json!("FS_OWNER_ONLY");
    let call = |req: axum::http::Request<axum::body::Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let body: Value = common::body_json(resp).await;
            (status, body)
        }
    };

    for uri in [
        "/api/hub/install",
        "/api/hub/retry-install",
        "/api/hub/update",
        "/api/hub/uninstall",
        "/api/extensions/enable",
        "/api/extensions/disable",
    ] {
        let body = json!({"name": "some-extension"});
        let (status, resp) = call(json_with_token("POST", uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {uri}: {resp}"
        );
        let (status, resp) = call(json_with_token("POST", uri, body, &desktop, "c")).await;
        assert_ne!(resp["code"], refused, "desktop {uri}: {status} {resp}");
    }
    for uri in ["/api/extensions", "/api/hub/extensions"] {
        let (status, resp) = call(get_with_token(uri, &phone)).await;
        assert_eq!(status, StatusCode::OK, "phone {uri}: {resp}");
    }
}
