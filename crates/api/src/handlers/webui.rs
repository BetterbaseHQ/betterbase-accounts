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
    let cache = if path.contains("/assets/") {
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
