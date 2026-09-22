//! React SPA handler: serve embedded assets with SPA fallback.

use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    response::IntoResponse,
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

/// Serve embedded assets.  Non-file paths (no extension) fall back to index.html.
pub async fn handle_spa(req: Request<Body>) -> Response<Body> {
    let path = req.uri().path().trim_start_matches('/');

    // Try exact match first
    if let Some(content) = Assets::get(path) {
        return serve_asset(path, content);
    }

    // For API/OAuth paths, let them 404 (they should have been handled by routes)
    if path.starts_with("v1/")
        || path.starts_with("oauth/")
        || path.starts_with(".well-known/")
        || path == "health"
        || path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
    {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Fallback to index.html for SPA navigation
    if let Some(index) = Assets::get("index.html") {
        return serve_asset("index.html", index);
    }

    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn serve_asset(path: &str, content: rust_embed::EmbeddedFile) -> Response<Body> {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else if path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=3600"
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from(content.data))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_assets_return_404_while_spa_routes_return_html() {
        for (path, status) in [
            ("/assets/missing.js", StatusCode::NOT_FOUND),
            ("/missing.css", StatusCode::NOT_FOUND),
            ("/v1/unknown", StatusCode::NOT_FOUND),
            ("/consent", StatusCode::OK),
        ] {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            assert_eq!(handle_spa(request).await.status(), status, "{path}");
        }
    }

    #[test]
    fn fingerprinted_assets_are_cached_immutably_but_html_is_revalidated() {
        let content = Assets::get("index.html").expect("web build includes index.html");
        let response = serve_asset("assets/app-fingerprint.js", content);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        let content = Assets::get("index.html").unwrap();
        let response = serve_asset("index.html", content);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
    }
}
