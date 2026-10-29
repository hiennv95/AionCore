//! Optional static web client served by the backend itself (`--static-dir` and `--legacy-static-dir`).
//!
//! Lets a browser host run `aioncore` alone, without a Node reverse proxy in
//! front of it. Paths the backend owns never fall through to the SPA, so an
//! unknown API route still answers 404 instead of `index.html`.
//!
//! When `--legacy-static-dir` is provided, the interim React WebUI is served
//! at `/legacy/` with a 308 trailing-slash redirect from `/legacy`, while the
//! root SPA (Svelte) remains at `/`.

use std::convert::Infallible;
use std::path::{Path, PathBuf};

use aionui_auth::security_headers_middleware;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware;
use axum::response::IntoResponse;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

/// Error returned when `--static-dir` or `--legacy-static-dir` cannot serve a web client.
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

/// A request for a file (its last segment has an extension) that is not in the build, e.g. a
/// hashed chunk of a previous release. It gets 404, not the SPA's index.html: a stale page
/// must not receive HTML where it asked for JavaScript or CSS (P3/P5 upgrades).
fn is_missing_asset(base: &Path, subpath: &str) -> bool {
    let last = subpath.rsplit('/').next().unwrap_or_default();
    !last.is_empty() && last.contains('.') && !base.join(subpath).is_file()
}

/// Cache policy for a static response. SvelteKit's `/_app/immutable/` files carry a content
/// hash in their name and never change; everything else (index.html, client routes,
/// `_app/version.json`, the legacy client) is revalidated so an upgrade is picked up at once.
fn cache_control(immutable: bool) -> HeaderValue {
    HeaderValue::from_static(if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    })
}

/// Helper to decode percent-encoded byte sequences (e.g. `%2e%2e` -> `..`).
fn percent_decode(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let hex_val = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            };
            let v1 = hex_val(h1)?;
            let v2 = hex_val(h2)?;
            bytes.push((v1 << 4) | v2);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}

/// Dotfiles and dot-directories (`.env`, `.git`, …) and traversal segments are never served.
fn has_hidden_segment(path: &str) -> bool {
    let check = |p: &str| {
        p.split('/').any(|segment| segment.starts_with('.')) || p.contains("/..") || p.contains("../") || p == ".."
    };
    if check(path) {
        return true;
    }
    if let Some(decoded) = percent_decode(path)
        && check(&decoded)
    {
        return true;
    }
    false
}

/// Verify that a file path on disk remains strictly contained inside the canonical base dir.
fn is_path_contained_in(base_canonical: &Path, file_path: &Path) -> bool {
    let is_symlink = file_path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if is_symlink || file_path.exists() {
        if let Ok(canonical) = dunce::canonicalize(file_path) {
            canonical.starts_with(base_canonical)
        } else {
            false
        }
    } else {
        // Non-existent path will fall back to index.html in the SPA service.
        true
    }
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

/// Serve static web clients: root SPA (e.g. Svelte) at `/` and/or legacy SPA (e.g. React) at `/legacy/`.
pub fn with_static_web_clients(router: Router, root_dir: Option<&Path>, legacy_dir: Option<&Path>) -> Router {
    if root_dir.is_none() && legacy_dir.is_none() {
        return router;
    }

    let root_setup = root_dir.map(|dir| {
        let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        let canonical = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        (dir.to_path_buf(), canonical, spa)
    });

    let legacy_setup = legacy_dir.map(|dir| {
        let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        let canonical = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        (dir.to_path_buf(), canonical, spa)
    });

    let fallback = Router::new()
        .fallback(move |mut request: Request| {
            let root_setup = root_setup.clone();
            let legacy_setup = legacy_setup.clone();
            async move {
                let path = request.uri().path().to_owned();

                // 1. Backend paths never resolve to either SPA.
                if is_backend_path(&path) {
                    return StatusCode::NOT_FOUND.into_response();
                }

                // 2. Dotfiles, hidden segments, and traversal attempts are rejected.
                if has_hidden_segment(&path) {
                    return StatusCode::NOT_FOUND.into_response();
                }

                // 3. Handle /legacy routes when legacy_dir is configured.
                if let Some((legacy_path, canonical_legacy, legacy_spa)) = &legacy_setup {
                    if path == "/legacy" {
                        // Trailing-slash redirect with HTTP 308, preserving query parameters.
                        let location = if let Some(query) = request.uri().query() {
                            format!("/legacy/?{query}")
                        } else {
                            "/legacy/".to_string()
                        };
                        return (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, location)]).into_response();
                    }

                    if path == "/legacy/" || path.starts_with("/legacy/") {
                        // Method guard: only GET and HEAD are allowed.
                        if request.method() != Method::GET && request.method() != Method::HEAD {
                            return StatusCode::METHOD_NOT_ALLOWED.into_response();
                        }

                        // Determine subpath relative to legacy root.
                        let subpath = if path == "/legacy/" {
                            ""
                        } else {
                            &path["/legacy/".len()..]
                        };

                        // Check containment and symlink escape.
                        if !subpath.is_empty() {
                            // Check the decoded path, which is what ServeDir opens (audit H3).
                            let Some(subpath) = percent_decode(subpath) else {
                                return StatusCode::NOT_FOUND.into_response();
                            };
                            let target = legacy_path.join(&subpath);
                            if !is_path_contained_in(canonical_legacy, &target) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                            if is_missing_asset(legacy_path, &subpath) {
                                return StatusCode::NOT_FOUND.into_response();
                            }
                        }

                        // Rewrite URI to relative path for ServeDir.
                        let rewritten_path = if subpath.is_empty() {
                            "/".to_string()
                        } else {
                            format!("/{}", subpath)
                        };
                        let rewritten_uri = if let Some(query) = request.uri().query() {
                            format!("{}?{}", rewritten_path, query)
                        } else {
                            rewritten_path
                        };

                        if let Ok(new_uri) = rewritten_uri.parse::<axum::http::Uri>() {
                            *request.uri_mut() = new_uri;
                        }

                        let response: Result<_, Infallible> = legacy_spa.clone().oneshot(request).await;
                        let mut res = match response {
                            Ok(res) => res.into_response(),
                        };
                        res.headers_mut().insert(header::CACHE_CONTROL, cache_control(false));
                        return res;
                    }
                }

                // 4. Handle root SPA when root_dir is configured.
                if let Some((root_path, canonical_root, root_spa)) = &root_setup {
                    // Method guard: only GET and HEAD are allowed for static files/SPA.
                    if request.method() != Method::GET && request.method() != Method::HEAD {
                        return StatusCode::METHOD_NOT_ALLOWED.into_response();
                    }

                    let subpath = path.trim_start_matches('/');
                    if !subpath.is_empty() {
                        // Check the decoded path, which is what ServeDir opens (audit H3).
                        let Some(subpath) = percent_decode(subpath) else {
                            return StatusCode::NOT_FOUND.into_response();
                        };
                        let target = root_path.join(&subpath);
                        if !is_path_contained_in(canonical_root, &target) {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        if is_missing_asset(root_path, &subpath) {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                    }

                    let immutable = path.starts_with("/_app/immutable/");
                    let response: Result<_, Infallible> = root_spa.clone().oneshot(request).await;
                    let mut res = match response {
                        Ok(res) => res.into_response(),
                    };
                    if res.status().is_success() {
                        res.headers_mut()
                            .insert(header::CACHE_CONTROL, cache_control(immutable));
                    }
                    res
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        })
        .layer(middleware::from_fn(security_headers_middleware));

    router.fallback_service(fallback)
}

/// Serve files from `dir` for every request no route matched, falling back to
/// `index.html` for client-side routes. Security headers match API responses.
pub fn with_static_web(router: Router, dir: &Path) -> Router {
    with_static_web_clients(router, Some(dir), None)
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

    /// P3/P5: after an upgrade a stale page asks for chunks that no longer exist. They must
    /// 404, not come back as index.html; client routes still fall back to the SPA.
    #[tokio::test]
    async fn a_missing_asset_is_404_but_a_client_route_is_the_spa() {
        let dir = web_dir();
        let (status, _, _) = get_path(app(dir.path()), "/_app/immutable/chunks/old.abc123.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = get_path(app(dir.path()), "/assets/gone.css").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, body, _) = get_path(app(dir.path()), "/c/8f2a91c0").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "<html>spa</html>"));
        let (status, body, _) = get_path(app(dir.path()), "/assets/app.js").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "console.log(1)"));
    }

    /// Hashed SvelteKit files are cached for good; the entry page and the rest are revalidated,
    /// so a new release is picked up on the next load.
    #[tokio::test]
    async fn only_hashed_files_are_cached_for_good() {
        let dir = web_dir();
        std::fs::create_dir_all(dir.path().join("_app/immutable/entry")).unwrap();
        std::fs::write(dir.path().join("_app/immutable/entry/start.Ab12.js"), "x").unwrap();
        std::fs::write(dir.path().join("_app/version.json"), "{}").unwrap();
        let cache = |r: &Response| r.headers()[header::CACHE_CONTROL].to_str().unwrap().to_owned();

        let (status, _, r) = get_path(app(dir.path()), "/_app/immutable/entry/start.Ab12.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cache(&r), "public, max-age=31536000, immutable");
        for path in ["/", "/c/8f2a91c0", "/_app/version.json", "/assets/app.js"] {
            let (status, _, r) = get_path(app(dir.path()), path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(cache(&r), "no-cache", "{path}");
        }
        let (_, _, r) = get_path(app(dir.path()), "/api/ping").await;
        assert!(
            !r.headers().contains_key(header::CACHE_CONTROL),
            "API responses are untouched"
        );
    }

    #[test]
    fn validate_requires_index_html() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_static_dir(dir.path()).is_err());
        std::fs::write(dir.path().join("index.html"), "x").unwrap();
        assert!(validate_static_dir(dir.path()).is_ok());
    }

    fn legacy_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>legacy-react</html>").unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/legacy.js"), "console.log('legacy')").unwrap();
        dir
    }

    fn dual_app(root: &Path, legacy: &Path) -> Router {
        with_static_web_clients(
            Router::new().route("/api/ping", get(|| async { "pong" })),
            Some(root),
            Some(legacy),
        )
    }

    #[tokio::test]
    async fn legacy_redirects_with_308_and_preserves_query() {
        let root = web_dir();
        let legacy = legacy_dir();
        let router = dual_app(root.path(), legacy.path());

        let response = router
            .clone()
            .oneshot(Request::builder().uri("/legacy").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/legacy/");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/legacy?redirect=%2Fconversation%2F1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/legacy/?redirect=%2Fconversation%2F1"
        );
    }

    /// Audit H3: containment must check the percent-decoded path ServeDir will open.
    #[cfg(unix)]
    #[tokio::test]
    async fn encoded_symlink_and_traversal_requests_do_not_escape() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "TOP-SECRET").unwrap();
        std::fs::write(outside.path().join("SECRET"), "TOP-SECRET").unwrap();
        let root = web_dir();
        let legacy = legacy_dir();
        std::os::unix::fs::symlink(outside.path(), root.path().join("my link")).unwrap();
        std::os::unix::fs::symlink(outside.path(), legacy.path().join("my link")).unwrap();
        let router = dual_app(root.path(), legacy.path());
        for path in [
            "/my%20link/secret.txt",
            "/my%20link/SECRET",
            "/legacy/my%20link/secret.txt",
            "/legacy/my%20link/SECRET",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/assets/%2e%2e%2f%2e%2e%2fetc/passwd",
            "/legacy/%2e%2e%2fsecret.txt",
        ] {
            let (status, body, _) = get_path(router.clone(), path).await;
            assert!(!body.contains("TOP-SECRET") && !body.contains("root:"), "{path}");
            assert_ne!(status, StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn encoded_asset_names_and_deep_links_still_work() {
        let root = web_dir();
        std::fs::write(root.path().join("assets/my file.js"), "spaced").unwrap();
        let router = app(root.path());
        let (status, body, _) = get_path(router.clone(), "/assets/my%20file.js").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "spaced"));
        let (status, body, _) = get_path(router, "/c/caf%C3%A9%20chat").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "<html>spa</html>"));
    }

    #[tokio::test]
    async fn legacy_serves_index_assets_and_deep_links() {
        let root = web_dir();
        let legacy = legacy_dir();
        let router = dual_app(root.path(), legacy.path());

        // /legacy/ serves legacy index.html
        let (status, body, res) = get_path(router.clone(), "/legacy/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>legacy-react</html>");
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");

        // deep path serves legacy index.html
        let (status, body, _) = get_path(router.clone(), "/legacy/conversation/123").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>legacy-react</html>");

        // assets served from legacy_dir
        let (status, body, res) = get_path(router.clone(), "/legacy/assets/legacy.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log('legacy')");
        assert_eq!(res.headers().get("x-content-type-options").unwrap(), "nosniff");

        // root / still serves Svelte
        let (status, body, _) = get_path(router.clone(), "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>spa</html>");

        // unknown /api still returns 404
        let (status, _, _) = get_path(router, "/api/unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn legacy_rejects_non_get_and_hidden_and_symlinks() {
        let root = web_dir();
        let legacy = legacy_dir();

        // Create secret dotfiles
        std::fs::write(legacy.path().join(".env"), "SECRET=LEGACY").unwrap();

        // Create an outside secret and symlink inside legacy
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "OUTSIDE_SECRET").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            legacy.path().join("assets/symlink_outside.txt"),
        )
        .unwrap();

        let router = dual_app(root.path(), legacy.path());

        // POST /legacy/ -> 405
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/legacy/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        // Dotfile -> 404
        let (status, body, _) = get_path(router.clone(), "/legacy/.env").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("SECRET"));

        // Encoded traversal /legacy/%2e%2e/ -> 404
        let (status, _, _) = get_path(router.clone(), "/legacy/%2e%2e/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Symlink escape -> 404
        #[cfg(unix)]
        {
            let (status, body, _) = get_path(router.clone(), "/legacy/assets/symlink_outside.txt").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(!body.contains("OUTSIDE_SECRET"));
        }
    }

    #[tokio::test]
    async fn legacy_missing_assets_404_and_pages_are_revalidated() {
        let root = web_dir();
        let legacy = legacy_dir();
        let app = dual_app(root.path(), legacy.path());
        let (status, _, _) = get_path(app.clone(), "/legacy/assets/old.123.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, r) = get_path(app.clone(), "/legacy/some/deep/link").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
    }

    #[tokio::test]
    async fn legacy_omitted_follows_existing_behavior() {
        let root = web_dir();
        // legacy is None: request to /legacy/ falls back to root SPA
        let router = with_static_web_clients(
            Router::new().route("/api/ping", get(|| async { "pong" })),
            Some(root.path()),
            None,
        );
        let (status, body, _) = get_path(router, "/legacy/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>spa</html>");
    }
}
