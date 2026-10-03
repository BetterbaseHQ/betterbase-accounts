use super::*;
use crate::test_support::{post_form, test_app, TestApp, TEST_ISSUER};
use axum::{body::Body, http::Request};
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::ServiceExt;

const REDIRECT: &str = "https://app.example.test/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const THUMBPRINT: &str = "kOFKxjJdOqJD5G4Yuw-cxHe64VGyxKEO_hoV83QfGj0";
const EXTENDED_CHALLENGE: &str = "gdwRhZ4LMabOsK2pZWOfloXIQ_U2BsHYceQP-cR6N-M";

async fn client(app: &TestApp) -> OAuthClient {
    let client = OAuthClient {
        id: Uuid::new_v4(),
        name: "Test".into(),
        secret_hash: None,
        redirect_uris: vec![REDIRECT.into()],
        allowed_scopes: vec!["sync".into(), "files".into()],
        created_at: chrono::Utc::now(),
    };
    app.storage.create_oauth_client(&client).await.unwrap();
    client
}
fn params(client: &OAuthClient) -> HashMap<String, String> {
    [
        ("client_id", client.id.to_string()),
        ("redirect_uri", REDIRECT.into()),
        ("state", "state&injected=yes".into()),
        ("response_type", "code".into()),
        ("scope", "openid".into()),
        ("code_challenge", CHALLENGE.into()),
        ("code_challenge_method", "S256".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}
async fn authorize(app: &TestApp, params: &HashMap<String, String>) -> Response {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/authorize?{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
fn redirect_params(response: &Response) -> (String, HashMap<String, String>) {
    let (base, query) = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .split_once('?')
        .unwrap();
    (
        base.into(),
        form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect(),
    )
}

#[tokio::test]
async fn authorize_never_redirects_to_an_unvalidated_client_or_uri() {
    let Some(app) = test_app().await else { return };
    let client = client(&app).await;
    for (key, value) in [
        ("client_id", None),
        ("client_id", Some("not-a-uuid")),
        ("client_id", Some("00000000-0000-0000-0000-000000000001")),
        ("redirect_uri", None),
        ("redirect_uri", Some("https://evil.test/callback")),
        (
            "redirect_uri",
            Some("https://app.example.test/callback/extra"),
        ),
        (
            "redirect_uri",
            Some("https://app.example.test/callback?next=evil"),
        ),
        (
            "redirect_uri",
            Some("https://app.example.test.evil.test/callback"),
        ),
        ("redirect_uri", Some("javascript:alert(1)")),
    ] {
        let mut params = params(&client);
        params.remove(key);
        if let Some(value) = value {
            params.insert(key.into(), value.into());
        }
        let response = authorize(&app, &params).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{key}={value:?}"
        );
        assert!(response.headers().get(header::LOCATION).is_none());
    }
}

#[tokio::test]
async fn authorize_rejects_invalid_parameters_without_losing_state_or_redirect_binding() {
    let Some(app) = test_app().await else { return };
    let client = client(&app).await;
    for (key, value, error) in [
        ("state", None, "invalid_request"),
        ("state", Some(""), "invalid_request"),
        ("response_type", None, "unsupported_response_type"),
        ("response_type", Some("token"), "unsupported_response_type"),
        ("code_challenge_method", None, "invalid_request"),
        ("code_challenge_method", Some("plain"), "invalid_request"),
        ("code_challenge", None, "invalid_request"),
        ("code_challenge", Some(""), "invalid_request"),
        ("code_challenge", Some("short"), "invalid_request"),
        ("scope", None, "invalid_request"),
        ("scope", Some(""), "invalid_request"),
        ("scope", Some("openid admin"), "invalid_scope"),
        ("scope", Some("inference"), "invalid_scope"),
        ("scope", Some("files"), "invalid_scope"),
        ("scope", Some("   "), "invalid_scope"),
        ("keys_jwk", Some("not-base64!"), "invalid_request"),
        ("keys_jwk", Some("e30"), "invalid_request"),
        ("keys_jwk", Some("bm90LWpzb24"), "invalid_request"),
    ] {
        let mut params = params(&client);
        params.remove(key);
        if let Some(value) = value {
            params.insert(key.into(), value.into());
        }
        let response = authorize(&app, &params).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{key}={value:?}");
        let (base, result) = redirect_params(&response);
        assert_eq!(base, REDIRECT, "{key}={value:?}");
        assert_eq!(
            result.get("error").map(String::as_str),
            Some(error),
            "{key}={value:?}"
        );
        assert!(!result.contains_key("injected"));
        if key != "state" {
            assert_eq!(result["state"], "state&injected=yes");
        }
    }
}

fn public_jwk() -> Value {
    let (_, public) = betterbase_accounts_auth::es256::generate_keypair().unwrap();
    let jwk = betterbase_accounts_auth::es256::Jwk::from_spki_der(1, &public).unwrap();
    json!({"kty": "EC", "crv": "P-256", "x": jwk.x, "y": jwk.y})
}

#[test]
fn p256_validation_rejects_private_malformed_and_off_curve_keys() {
    let valid = public_jwk();
    assert_eq!(validate_p256_public_key(&valid).unwrap(), valid);
    let mut extra = valid.clone();
    extra["kid"] = "extra".into();
    assert_eq!(validate_p256_public_key(&extra).unwrap(), valid);
    for (field, value) in [
        ("kty", json!("RSA")),
        ("crv", json!("P-384")),
        ("d", json!("secret")),
        ("d", Value::Null),
        ("x", Value::Null),
        ("y", json!(123)),
        ("x", json!("!")),
        ("y", json!("!")),
        ("x", json!(B64URL.encode([0; 31]))),
        ("y", json!(B64URL.encode([0; 33]))),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(
            validate_p256_public_key(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
    for invalid in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"kty":"EC", "crv":"P-256", "x":B64URL.encode([0;32]), "y":B64URL.encode([0;32])}),
    ] {
        assert!(validate_p256_public_key(&invalid).is_err());
    }
}

#[tokio::test]
async fn authorize_accepts_allowed_scopes_and_a_valid_recipient_in_signed_state() {
    let Some(app) = test_app().await else { return };
    let client = client(&app).await;
    let jwk = public_jwk();
    for scope in ["openid profile email", "sync", "openid sync files"] {
        let mut params = params(&client);
        params.insert("scope".into(), scope.into());
        params.insert(
            "keys_jwk".into(),
            B64URL.encode(serde_json::to_vec(&jwk).unwrap()),
        );
        let response = authorize(&app, &params).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let (base, result) = redirect_params(&response);
        assert_eq!(base, "https://accounts.example.test/consent");
        assert_eq!(result.len(), 1);
        let claims = app
            .jwt
            .validate_oauth_state_token(&result["oauth"])
            .unwrap();
        assert_eq!(claims.scope, scope);
        assert_eq!(claims.redirect_uri, REDIRECT);
        assert_eq!(claims.keys_jwk, Some(jwk.clone()));
    }
    // P-256 coordinate lengths alone are not sufficient at the route boundary.
    let mut params = params(&client);
    params.insert("keys_jwk".into(), B64URL.encode(serde_json::to_vec(&json!({"kty":"EC", "crv":"P-256", "x":B64URL.encode([0;32]), "y":B64URL.encode([0;32])})).unwrap()));
    let response = authorize(&app, &params).await;
    assert_eq!(redirect_params(&response).1["error"], "invalid_request");
}

#[tokio::test]
async fn extended_pkce_binds_verifier_and_recipient_and_delivers_keys_once() {
    let Some(app) = test_app().await else { return };
    let client = client(&app).await;
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    for defect in [
        "none",
        "missing-thumbprint",
        "wrong-thumbprint",
        "wrong-verifier",
        "standard-challenge",
    ] {
        let code = Uuid::new_v4().to_string();
        app.storage
            .create_oauth_code(&OAuthCode {
                code: code.clone(),
                client_id: client.id,
                account_id: account.id,
                redirect_uri: REDIRECT.into(),
                scope: "openid sync".into(),
                code_challenge: if defect == "standard-challenge" {
                    CHALLENGE
                } else {
                    EXTENDED_CHALLENGE
                }
                .into(),
                keys_jwe: Some("encrypted-key-bundle".into()),
                keys_jwk_thumbprint: Some(THUMBPRINT.into()),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", &client.id.to_string()),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                (
                    "code_verifier",
                    if defect == "wrong-verifier" {
                        "wrong"
                    } else {
                        VERIFIER
                    },
                ),
                (
                    "keys_jwk_thumbprint",
                    match defect {
                        "missing-thumbprint" => "",
                        "wrong-thumbprint" => "wrong",
                        _ => THUMBPRINT,
                    },
                ),
            ])
            .finish();
        let (status, body) = post_form(&app, "/oauth/token", None, &form).await;
        if defect == "none" {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["keys_jwe"], "encrypted-key-bundle");
            let claims = app
                .jwt
                .validate_oauth_access_token(body["access_token"].as_str().unwrap())
                .unwrap();
            assert!(claims.aud.contains(&"betterbase-sync".into()));
            assert_eq!(claims.sub, account.id.to_string());
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{defect}: {body}");
            assert_eq!(body["error"], "invalid_grant");
            assert!(body.get("keys_jwe").is_none());
            assert!(body.get("access_token").is_none());
        }
        assert_eq!(
            post_form(&app, "/oauth/token", None, &form).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn concurrent_code_exchanges_issue_only_one_session() {
    let Some(app) = test_app().await else { return };
    let client = client(&app).await;
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let code = "one-use-code";
    app.storage
        .create_oauth_code(&OAuthCode {
            code: code.into(),
            client_id: client.id,
            account_id: account.id,
            redirect_uri: REDIRECT.into(),
            scope: "openid".into(),
            code_challenge: CHALLENGE.into(),
            keys_jwe: None,
            keys_jwk_thumbprint: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .unwrap();
    let form = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", &client.id.to_string()),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ])
        .finish();
    let (a, b) = tokio::join!(
        post_form(&app, "/oauth/token", None, &form),
        post_form(&app, "/oauth/token", None, &form)
    );
    let mut successes = 0;
    for (status, body) in [a, b] {
        match status {
            StatusCode::OK => {
                successes += 1;
                assert!(body["access_token"].is_string());
            }
            StatusCode::BAD_REQUEST => assert_eq!(body["error"], "invalid_grant"),
            other => panic!("unexpected status: {other}: {body}"),
        }
    }
    assert_eq!(successes, 1);
}
