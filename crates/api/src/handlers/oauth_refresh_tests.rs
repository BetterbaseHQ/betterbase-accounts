use axum::http::StatusCode;

use crate::test_support::{post_form, test_app};

use super::*;

const REDIRECT_URI: &str = "http://localhost:5381/";

/// Seed client + account + grant + one active refresh token; return
/// (client_id, raw_refresh_token).
async fn seed_refresh_token(app: &crate::test_support::TestApp) -> (String, String) {
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "refresh test client".to_owned(),
            secret_hash: None,
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");
    let tail = &client_id.simple().to_string()[..12];
    let account = app
        .storage
        .get_or_create_account(
            crate::test_support::TEST_ISSUER,
            &format!("user{tail}"),
            &format!("user{tail}@example.test"),
        )
        .await
        .expect("create account");
    let grant = app
        .storage
        .get_or_create_oauth_grant(client_id, account.id, "openid")
        .await
        .expect("create grant");

    let raw = generate_random_token();
    let now = chrono::Utc::now();
    app.storage
        .create_refresh_token(&OAuthRefreshToken {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            token_hash: sha256_hash(raw.as_bytes()),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
        })
        .await
        .expect("create refresh token");
    (client_id.to_string(), raw)
}

fn refresh_form(client_id: &str, token: &str) -> String {
    format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        token, client_id
    )
}

#[tokio::test]
async fn sequential_reuse_of_rotated_token_revokes_surviving_family() {
    let Some(app) = test_app().await else {
        return;
    };
    let (client_id, raw1) = seed_refresh_token(&app).await;

    // Legitimate rotation.
    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw1)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let raw2 = body["refresh_token"]
        .as_str()
        .expect("new token")
        .to_owned();

    // AUD-004 sequential reuse: the already-rotated token is presented
    // again (a copied token used by its thief, or a stale tab). The
    // surviving replacement must be revoked, not left active. 400 per
    // RFC 6749; the description carries the reuse signal.
    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("reuse"),
        "body: {body}"
    );

    // The replacement family is dead. A revoked token was deleted
    // without being recorded as used, so it presents as a plain
    // invalid_grant (400) rather than a reuse detection (401).
    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw2)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn concurrent_presentation_of_one_token_kills_family() {
    let Some(app) = test_app().await else {
        return;
    };
    let (client_id, raw1) = seed_refresh_token(&app).await;

    // Two in-flight refreshes presenting the same token: exactly one
    // rotation can win; the loser's duplicate insert must revoke the
    // family (including the winner's fresh replacement) instead of
    // erroring with a broken transaction and leaving it alive.
    let (r1, r2) = {
        let form = refresh_form(&client_id, &raw1);
        tokio::join!(
            post_form(&app, "/oauth/token", None, &form),
            post_form(&app, "/oauth/token", None, &form),
        )
    };
    let ok_count = usize::from(r1.0 == StatusCode::OK) + usize::from(r2.0 == StatusCode::OK);
    assert_eq!(ok_count, 1, "responses: {r1:?} {r2:?}");
    let raw2 = if r1.0 == StatusCode::OK { r1.1 } else { r2.1 }["refresh_token"]
        .as_str()
        .expect("new token")
        .to_owned();

    // Family revoked: the winner's replacement no longer refreshes.
    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw2)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// Seed a client + account + refreshable grant with an explicit grant
/// scope and client allowed-scopes (storage-level grant creation does
/// not re-validate policy, which is what these tests vary).
async fn seed_scoped_refresh(
    app: &crate::test_support::TestApp,
    allowed: &[&str],
    grant_scope: &str,
) -> (String, String, Uuid) {
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "scope test client".to_owned(),
            secret_hash: None,
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            allowed_scopes: allowed.iter().map(|s| s.to_string()).collect(),
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");
    let tail = &client_id.simple().to_string()[..12];
    let account = app
        .storage
        .get_or_create_account(
            crate::test_support::TEST_ISSUER,
            &format!("user{tail}"),
            &format!("user{tail}@example.test"),
        )
        .await
        .expect("create account");
    let grant = app
        .storage
        .get_or_create_oauth_grant(client_id, account.id, grant_scope)
        .await
        .expect("create grant");

    let raw = generate_random_token();
    let now = chrono::Utc::now();
    app.storage
        .create_refresh_token(&OAuthRefreshToken {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            token_hash: sha256_hash(raw.as_bytes()),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
        })
        .await
        .expect("create refresh token");
    (client_id.to_string(), raw, account.id)
}

#[tokio::test]
async fn refresh_grants_the_latest_authorized_scope_not_the_first() {
    // AUD-013: a broad consent followed by a later narrow authorization
    // must not let refresh resurrect the broad scope.
    let Some(app) = test_app().await else {
        return;
    };
    let (client_id, raw, account_id) =
        seed_scoped_refresh(&app, &["openid", "sync"], "openid sync").await;

    // A later, narrower authorization for the same account+client (the
    // code-exchange path): the stored grant must track it.
    let narrow = app
        .storage
        .get_or_create_oauth_grant(Uuid::parse_str(&client_id).unwrap(), account_id, "openid")
        .await
        .expect("narrow authorization");
    assert_eq!(narrow.scope, "openid", "grant must track the latest scope");

    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["scope"], "openid",
        "refresh must not regain the broad scope: {body}"
    );
}

#[tokio::test]
async fn refresh_fails_when_the_client_lost_the_capability() {
    // AUD-013: a capability withdrawn from the client after consent must
    // stop flowing on refresh.
    let Some(app) = test_app().await else {
        return;
    };
    // Grant (storage-level) holds "openid sync", but the client's policy
    // only permits "openid".
    let (client_id, raw, _account_id) = seed_scoped_refresh(&app, &["openid"], "openid sync").await;

    let (status, body) =
        post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer permitted"),
        "body: {body}"
    );
}
