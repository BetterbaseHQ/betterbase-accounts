use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::json;
use tower::ServiceExt;

use crate::test_support::{get_json, post_json, test_app, TestApp, TEST_ISSUER};

use super::*;

const REDIRECT_URI: &str = "http://localhost:5381/";
const REDIRECT_URI_ENC: &str = "http%3A%2F%2Flocalhost%3A5381%2F";

#[tokio::test]
async fn consent_requires_auth_and_signed_state_and_denial_issues_no_code() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, None);
    let approved = json!({"oauth_state": state, "approved": true});
    for auth in [None, Some("invalid")] {
        let (status, body) = post_json(&app, "/oauth/consent", auth, &approved).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    for body in [
        json!({"approved": true}),
        json!({"oauth_state": "invalid", "approved": true}),
    ] {
        let (status, error) = post_json(&app, "/oauth/consent", Some(&token), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert!(error.get("redirect_uri").is_none());
    }
    let (status, denied) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({"oauth_state": state, "approved": false, "wrapped_scoped_key": "!"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    let redirect = denied["redirect_uri"].as_str().unwrap();
    let (base, query) = redirect.split_once('?').unwrap();
    assert_eq!(base, REDIRECT_URI);
    let params: std::collections::HashMap<_, _> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], "client-state");
    assert!(!params.contains_key("code"));
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM oauth_grants), (SELECT COUNT(*) FROM oauth_codes)",
    )
    .fetch_one(app.storage.pool())
    .await
    .unwrap();
    assert_eq!(counts, (0, 0));
}

fn keys_jwk() -> serde_json::Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64URL.encode([1u8; 32]),
        "y": B64URL.encode([2u8; 32]),
    })
}

/// Known-answer vector pinning the RFC 7638 construction shared by the
/// server, the browser (`computeJwkThumbprint`), and the SDK. A drift in
/// any implementation breaks extended PKCE at runtime only.
#[test]
fn jwk_thumbprint_matches_the_shared_known_answer() {
    let jwk = keys_jwk();
    assert_eq!(
        jwk_thumbprint_b64(&jwk).expect("thumbprint"),
        // SHA-256 over {"crv":"P-256","kty":"EC","x":"AQEB...","y":"AgIC..."}
        "kOFKxjJdOqJD5G4Yuw-cxHe64VGyxKEO_hoV83QfGj0"
    );
}

#[tokio::test]
async fn authorize_redirect_carries_only_the_signed_state_token() {
    // AUD-005: the consent URL must contain ONLY the signed `oauth`
    // token — reintroducing unsigned params (client name, keys, scope)
    // would let them be spoofed on the consent page.
    let Some(app) = test_app().await else {
        return;
    };
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "Spoofable Name".to_owned(),
            secret_hash: None,
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");

    let uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&response_type=code&scope=openid%20sync&state=client-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(&uri)
        .body(axum::body::Body::empty())
        .expect("build request");
    let response = app.router.clone().oneshot(request).await.expect("dispatch");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location header")
        .to_owned();

    let (base, query) = location.split_once('?').expect("consent query");
    assert!(
        base.ends_with("/consent"),
        "unexpected consent base: {base}"
    );
    let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(
        pairs.len(),
        1,
        "consent redirect must carry exactly one param: {location}"
    );
    assert_eq!(pairs[0].0, "oauth");
    // The token is a signed JWT (three segments), not a passthrough of
    // any client-supplied value.
    assert_eq!(pairs[0].1.split('.').count(), 3);
}

#[tokio::test]
async fn consent_rejects_partial_key_delivery_pair() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, Some(keys_jwk()));

    // thumbprint without keys_jwe
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state.clone(),
            "approved": true,
            "keys_jwk_thumbprint": "irrelevant",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "keys_jwe and keys_jwk_thumbprint must be supplied together"
    );

    // keys_jwe without thumbprint
    let (status, _) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state,
            "approved": true,
            "keys_jwe": "some-jwe",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_requires_key_delivery_for_the_sync_flow() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    // The signed state carries a recipient and the sync scope, but the
    // consent posts no key delivery: a silent downgrade must fail loudly.
    let state = state_token(&app, &client_id, Some(keys_jwk()));

    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state,
            "approved": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "keys_jwe and keys_jwk_thumbprint must be supplied together"
    );
}

async fn app_with_client_and_account() -> Option<(TestApp, String, String)> {
    let app = test_app().await?;
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "Test Client".to_owned(),
            secret_hash: None,
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");

    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "consenter", "consenter@example.test")
        .await
        .expect("create account");
    let token = app.auth_token(&account.id.to_string());
    Some((app, client_id.to_string(), token))
}

fn state_token(app: &TestApp, client_id: &str, keys_jwk: Option<serde_json::Value>) -> String {
    app.jwt
        .create_oauth_state_token(OAuthStateClaims::new(
            client_id.to_owned(),
            REDIRECT_URI.to_owned(),
            "openid sync".to_owned(),
            "client-state".to_owned(),
            "challenge".to_owned(),
            "S256".to_owned(),
            keys_jwk,
        ))
        .expect("state token")
}

#[tokio::test]
async fn consent_rejects_thumbprint_that_does_not_match_signed_recipient() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, Some(keys_jwk()));

    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state,
            "approved": true,
            "keys_jwe": "some-jwe",
            "keys_jwk_thumbprint": "attacker-chosen-thumbprint",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "keys_jwk_thumbprint does not match the authorization request"
    );
}

#[tokio::test]
async fn consent_accepts_thumbprint_matching_signed_recipient() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let jwk = keys_jwk();
    let state = state_token(&app, &client_id, Some(jwk.clone()));
    let thumbprint = jwk_thumbprint_b64(&jwk).expect("thumbprint");

    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state,
            "approved": true,
            "keys_jwe": "some-jwe",
            "keys_jwk_thumbprint": thumbprint,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let redirect = body["redirect_uri"].as_str().expect("redirect");
    assert!(redirect.starts_with(REDIRECT_URI));
    assert!(redirect.contains("code="));
}

#[tokio::test]
async fn consent_rejects_key_delivery_without_a_signed_recipient() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, None);

    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &json!({
            "oauth_state": state,
            "approved": true,
            "keys_jwe": "some-jwe",
            "keys_jwk_thumbprint": "whatever",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "authorization request did not include a key recipient"
    );
}

#[tokio::test]
async fn consent_context_returns_fields_from_the_signed_state() {
    let Some((app, client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, Some(keys_jwk()));

    let (status, body) = get_json(
        &app,
        &format!("/oauth/consent-context?oauth_state={state}"),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], client_id);
    assert_eq!(body["client_name"], "Test Client");
    assert_eq!(body["scope"], "openid sync");
    assert_eq!(body["redirect_uri"], REDIRECT_URI);
    assert_eq!(body["keys_jwk"]["kty"], "EC");
}

#[tokio::test]
async fn consent_context_rejects_invalid_state() {
    let Some((app, _client_id, token)) = app_with_client_and_account().await else {
        return;
    };
    let (status, _) = get_json(
        &app,
        "/oauth/consent-context?oauth_state=not-a-jwt",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_context_requires_authentication() {
    let Some((app, client_id, _token)) = app_with_client_and_account().await else {
        return;
    };
    let state = state_token(&app, &client_id, None);
    let (status, _) = get_json(
        &app,
        &format!("/oauth/consent-context?oauth_state={state}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
