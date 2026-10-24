//! Optional static web client served by the backend itself (`--static-dir`).
//!
//! Lets a browser host run `aioncore` alone, without a Node reverse proxy in
//! front of it. Paths the backend owns never fall through to the SPA, so an
//! unknown API route still answers 404 instead of `index.html`.

use std::convert::Infallible;
use std::path::{Path, PathBuf};

use aionui_auth::security_headers_middleware;
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

/// Error returned when `--static-dir` cannot serve a web client.
#[derive(Debug)]
pub struct StaticDirError {
    pub path: PathBuf,
}

impl std::fmt::Display for StaticDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "static dir {} has no index.html", self.path.display())
    }
}

impl std::error::Error for StaticDirError {}

/// Path prefixes owned by the backend; they must never resolve to the SPA.
fn is_backend_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/") || path == "/ws" || path == "/login" || path == "/logout"
}

/// Dotfiles and dot-directories (`.env`, `.git`, …) are never served, even if a
/// build accidentally copies them into the static dir.
fn has_hidden_segment(path: &str) -> bool {
    path.split('/').any(|segment| segment.starts_with('.'))
}

/// Check that `dir` looks like a built web client before the server starts.
pub fn validate_static_dir(dir: &Path) -> Result<(), StaticDirError> {
    if dir.join("index.html").is_file() {
        Ok(())
    } else {
        Err(StaticDirError {
            path: dir.to_path_buf(),
        })
    }
}

/// Serve files from `dir` for every request no route matched, falling back to
/// `index.html` for client-side routes. Security headers match API responses.
pub fn with_static_web(router: Router, dir: &Path) -> Router {
    let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
    let fallback = Router::new()
        .fallback(move |request: Request| {
            let spa = spa.clone();
            async move {
                let path = request.uri().path();
                if is_backend_path(path) || has_hidden_segment(path) {
                    return StatusCode::NOT_FOUND.into_response();
                }
                let response: Result<_, Infallible> = spa.oneshot(request).await;
                match response {
                    Ok(response) => response.into_response(),
                }
            }
        })
        .layer(middleware::from_fn(security_headers_middleware));
    router.fallback_service(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::response::Response;
    use axum::routing::get;

    fn web_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>spa</html>").unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app.js"), "console.log(1)").unwrap();
        dir
    }

    async fn get_path(router: Router, path: &str) -> (StatusCode, String, Response) {
        let response = router
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            Response::from_parts(parts, Body::empty()),
        )
    }

    fn app(dir: &Path) -> Router {
        with_static_web(Router::new().route("/api/ping", get(|| async { "pong" })), dir)
    }

    #[tokio::test]
    async fn api_routes_still_win() {
        let dir = web_dir();
        let (status, body, _) = get_path(app(dir.path()), "/api/ping").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pong");
    }

    #[tokio::test]
    async fn serves_assets_and_index() {
        let dir = web_dir();
        let (status, body, response) = get_path(app(dir.path()), "/assets/app.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log(1)");
        assert_eq!(response.headers().get("x-content-type-options").unwrap(), "nosniff");

        let (status, body, response) = get_path(app(dir.path()), "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>spa</html>");
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn client_routes_fall_back_to_index() {
        let dir = web_dir();
        let (status, body, _) = get_path(app(dir.path()), "/conversation/abc").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>spa</html>");
    }

    #[tokio::test]
    async fn unknown_backend_paths_are_not_the_spa() {
        let dir = web_dir();
        for path in ["/api/unknown", "/api", "/ws", "/login", "/logout"] {
            let (status, body, _) = get_path(app(dir.path()), path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(!body.contains("spa"), "{path}");
        }
    }

    #[tokio::test]
    async fn hidden_files_are_never_served() {
        let dir = web_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "[core]").unwrap();
        for path in ["/.env", "/.git/config", "/assets/.hidden"] {
            let (status, body, _) = get_path(app(dir.path()), path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(!body.contains("SECRET") && !body.contains("[core]"), "{path}");
        }
    }

    #[tokio::test]
    async fn only_read_methods_are_served() {
        let dir = web_dir();
        let response = app(dir.path())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/index.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn path_traversal_does_not_escape_the_dir() {
        let dir = web_dir();
        let (_, body, _) = get_path(app(dir.path()), "/../../../../etc/passwd").await;
        assert!(!body.contains("root:"));
    }

    #[test]
    fn validate_requires_index_html() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_static_dir(dir.path()).is_err());
        std::fs::write(dir.path().join("index.html"), "x").unwrap();
        assert!(validate_static_dir(dir.path()).is_ok());
    }
}
