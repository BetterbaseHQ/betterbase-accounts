//! Exercise security boundaries through the public router and real PostgreSQL.
use crate::test_support::{get_json, post_form, post_json, test_app, TEST_ISSUER};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use betterbase_accounts_storage::{
    AccountStorage, OAuthClientStorage, OAuthCodeStorage, VerificationStorage,
};
use chrono::{Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn key_routes_require_auth_and_enforce_material_boundaries_and_isolation() {
    let Some(app) = test_app().await else { return };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let other = app
        .storage
        .get_or_create_account(TEST_ISSUER, "bob", "bob@example.test")
        .await
        .unwrap();
    let token = app.auth_token(&account.id.to_string());
    for auth in [None, Some("garbage")] {
        assert_eq!(
            get_json(&app, "/v1/keys", auth).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for (service, name, material, expected) in [
        ("sync", "key", "ab".repeat(15), StatusCode::BAD_REQUEST),
        ("sync", "key", "ab".repeat(16), StatusCode::NO_CONTENT),
        ("sync", "key", "ab".repeat(128), StatusCode::NO_CONTENT),
        ("sync", "key", "ab".repeat(129), StatusCode::BAD_REQUEST),
        ("sync", "key", "zz".repeat(16), StatusCode::BAD_REQUEST),
        ("sync", "key", "a".repeat(33), StatusCode::BAD_REQUEST),
        ("unknown", "key", "ab".repeat(16), StatusCode::BAD_REQUEST),
        (
            "accounts",
            "12345678901234567890123456789012",
            "ab".repeat(16),
            StatusCode::NO_CONTENT,
        ),
        (
            "accounts",
            "123456789012345678901234567890123",
            "ab".repeat(16),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/keys/{service}/{name}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"keyMaterial": material}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "service={service}, name={name}, bytes={}",
            material.len()
        );
    }
    let (status, key) = get_json(&app, "/v1/keys/sync/key", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(key["serialNumber"], 2);
    assert_eq!(key["keyMaterial"], "ab".repeat(128));
    let other_token = app.auth_token(&other.id.to_string());
    assert_eq!(
        get_json(&app, "/v1/keys/sync/key", Some(&other_token))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_json(&app, "/v1/keys", Some(&other_token)).await.1,
        json!([])
    );
}

#[tokio::test]
async fn router_rejects_oversized_and_malformed_json_with_protocol_header() {
    let Some(app) = test_app().await else { return };
    for (body, status) in [
        ("{".to_owned(), StatusCode::BAD_REQUEST),
        ("x".repeat(64 * 1024 + 1), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/init")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["x-protocol-version"], "1");
    }
}

#[tokio::test]
async fn verification_rejects_bad_format_and_wrong_binding_then_consumes_once() {
    let Some(app) = test_app().await else { return };
    app.storage
        .create_verification_code(&betterbase_accounts_storage::VerificationCode {
            id: Uuid::new_v4(),
            email: "alice@example.test".into(),
            purpose: "registration".into(),
            code_hash: Sha256::digest(b"012345").to_vec(),
            attempts: 0,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    for (email, purpose, code) in [
        ("alice@example.test", "registration", "12345"),
        ("alice@example.test", "registration", "1234567"),
        ("alice@example.test", "registration", "abcdef"),
        ("alice@example.test", "registration", "１２"),
        ("alice@example.test", "invalid", "012345"),
        ("bob@example.test", "registration", "012345"),
        ("alice@example.test", "recovery", "012345"),
    ] {
        let (status, _) = post_json(
            &app,
            "/v1/accounts/verify/confirm",
            None,
            &json!({"email": email, "purpose": purpose, "code": code}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let request =
        json!({"email": "alice@EXAMPLE.TEST", "purpose": "registration", "code": "012345"});
    let (status, body) = post_json(&app, "/v1/accounts/verify/confirm", None, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = app
        .jwt
        .validate_verification_token(body["verification_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.email, "alice@example.test");
    assert_eq!(claims.purpose, "registration");
    assert_eq!(
        post_json(&app, "/v1/accounts/verify/confirm", None, &request)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn authorization_code_exchange_binds_pkce_client_redirect_and_expiry() {
    let Some(app) = test_app().await else { return };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&betterbase_accounts_storage::OAuthClient {
            id: client_id,
            name: "Test".into(),
            secret_hash: None,
            redirect_uris: vec!["https://app.test/cb".into()],
            allowed_scopes: vec!["openid".into()],
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    // RFC 7636 known-answer pair, independent of the production hash helper.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    for defect in ["none", "verifier", "client", "redirect", "expired"] {
        let code = Uuid::new_v4().to_string();
        app.storage
            .create_oauth_code(&betterbase_accounts_storage::OAuthCode {
                code: code.clone(),
                client_id,
                account_id: account.id,
                redirect_uri: "https://app.test/cb".into(),
                scope: "openid".into(),
                code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
                keys_jwe: None,
                keys_jwk_thumbprint: None,
                created_at: Utc::now(),
                expires_at: Utc::now()
                    + Duration::minutes(if defect == "expired" { -1 } else { 5 }),
            })
            .await
            .unwrap();
        let form = format!("grant_type=authorization_code&client_id={}&code={code}&redirect_uri={}&code_verifier={}",
            if defect == "client" { Uuid::new_v4() } else { client_id },
            if defect == "redirect" { "https%3A%2F%2Fevil.test%2Fcb" } else { "https%3A%2F%2Fapp.test%2Fcb" },
            if defect == "verifier" { "wrong" } else { verifier });
        let (status, body) = post_form(&app, "/oauth/token", None, &form).await;
        if defect == "none" {
            assert_eq!(status, StatusCode::OK, "{body}");
            let claims = app
                .jwt
                .validate_oauth_access_token(body["access_token"].as_str().unwrap())
                .unwrap();
            assert_eq!(claims.sub, account.id.to_string());
            assert_eq!(claims.aud, vec![client_id.to_string()]);
            assert!(!body["refresh_token"].as_str().unwrap().is_empty());
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{defect}: {body}");
            assert_eq!(body["error"], "invalid_grant");
            assert!(body.get("access_token").is_none());
        }
        let (status, body) = post_form(&app, "/oauth/token", None, &form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "code cannot be replayed");
    }
}

#[tokio::test]
async fn oauth_userinfo_authenticates_access_tokens_and_limits_disclosed_claims() {
    use betterbase_accounts_auth::jwt::OAuthAccessClaims;
    let Some(app) = test_app().await else {
        return;
    };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    let client_id = Uuid::new_v4().to_string();
    let claims = OAuthAccessClaims {
        sub: account.id.to_string(),
        iss: TEST_ISSUER.into(),
        aud: vec![client_id.clone()],
        iat: now,
        exp: now + 600,
        client_id,
        grant_id: Uuid::new_v4().to_string(),
        scope: "openid".into(),
        did: "did:key:test".into(),
        personal_space_id: Uuid::new_v4().to_string(),
        mailbox_id: None,
    };
    for auth in [
        None,
        Some("garbage".to_owned()),
        Some(app.auth_token(&account.id.to_string())),
    ] {
        assert_eq!(
            get_json(&app, "/oauth/userinfo", auth.as_deref()).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for invalid in ["expired", "issuer", "audience", "subject", "signature"] {
        let mut bad = claims.clone();
        match invalid {
            "expired" => bad.exp = now - 3600,
            "issuer" => bad.iss = "https://foreign.example.test".into(),
            "audience" => bad.aud = vec!["https://foreign.example.test".into()],
            "subject" => bad.sub = "not-a-uuid".into(),
            _ => {}
        }
        let mut token = app.jwt.create_oauth_access_token(bad).unwrap();
        if invalid == "signature" {
            let start = token.rfind('.').unwrap() + 1;
            let replacement = if &token[start..start + 1] == "A" {
                "B"
            } else {
                "A"
            };
            token.replace_range(start..start + 1, replacement);
        }
        assert_eq!(
            get_json(&app, "/oauth/userinfo", Some(&token)).await.0,
            StatusCode::UNAUTHORIZED,
            "{invalid}"
        );
    }
    for scope in [
        "sync",
        "openid",
        "openid profile",
        "openid email",
        "openid profile email",
    ] {
        let mut scoped = claims.clone();
        scoped.scope = scope.into();
        let token = app.jwt.create_oauth_access_token(scoped).unwrap();
        let (status, body) = get_json(&app, "/oauth/userinfo", Some(&token)).await;
        if scope == "sync" {
            assert_eq!(status, StatusCode::FORBIDDEN);
            continue;
        }
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["sub"], account.id.to_string());
        if scope.contains("email") {
            assert_eq!(body["email"], account.email);
            assert_eq!(body["email_verified"], true);
        } else {
            assert!(body["email"].is_null());
            assert!(body["email_verified"].is_null());
        }
        if scope.contains("profile") {
            assert_eq!(body["preferred_username"], "alice@accounts.example.test");
        } else {
            assert!(body["preferred_username"].is_null());
        }
    }
}
