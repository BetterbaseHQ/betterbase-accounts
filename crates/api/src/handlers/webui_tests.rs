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
