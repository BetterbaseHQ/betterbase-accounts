//! Account deletion and OAuth resource contracts through the real HTTP router.
use crate::test_support::{get_json, post_form, post_json, test_app, TestApp, TEST_ISSUER};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use betterbase_accounts_auth::jwt::OAuthAccessClaims;
use betterbase_accounts_storage::{
    Account, AccountStorage, OAuthClient, OAuthClientStorage, OAuthGrant, OAuthGrantStorage,
    RecoveryStorage, StorageError,
};
use chrono::{Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

async fn client(app: &TestApp) -> Uuid {
    let id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id,
            name: "resource tests".into(),
            secret_hash: None,
            redirect_uris: vec!["https://example.test/callback".into()],
            allowed_scopes: vec!["sync".into()],
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    id
}

async fn account(app: &TestApp, client_id: Uuid, username: &str) -> (Account, OAuthGrant) {
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, username, &format!("{username}@example.test"))
        .await
        .unwrap();
    app.storage
        .finalize_registration_with_root_key(account.id, b"record", &[1; 41])
        .await
        .unwrap();
    let grant = app
        .storage
        .get_or_create_oauth_grant(client_id, account.id, "openid profile email sync")
        .await
        .unwrap();
    (account, grant)
}

fn claims(account: &Account, grant: &OAuthGrant) -> OAuthAccessClaims {
    OAuthAccessClaims {
        sub: account.id.to_string(),
        iss: TEST_ISSUER.into(),
        aud: vec![grant.client_id.to_string()],
        exp: (Utc::now() + Duration::minutes(10)).timestamp(),
        iat: Utc::now().timestamp(),
        client_id: grant.client_id.to_string(),
        grant_id: grant.id.to_string(),
        scope: grant.scope.clone(),
        did: "did:key:test".into(),
        personal_space_id: Uuid::new_v4().to_string(),
        mailbox_id: None,
    }
}

async fn delete(app: &TestApp, token: Option<&str>) -> StatusCode {
    let mut request = Request::builder().method("DELETE").uri("/v1/accounts");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["x-protocol-version"], "1");
    response.status()
}

async fn populate_dependents(app: &TestApp, account: &Account, grant: &OAuthGrant) -> String {
    let pool = app.storage.pool();
    for table in ["registration_states", "login_states"] {
        let (extra_column, extra_value) = if table == "login_states" {
            (", state", ", 'state'::bytea")
        } else {
            ("", "")
        };
        sqlx::query(&format!("INSERT INTO {table} (id, account_id, username, expires_at{extra_column}) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour'{extra_value})"))
            .bind(Uuid::new_v4()).bind(account.id).bind(&account.username).execute(pool).await.unwrap();
    }
    sqlx::query("INSERT INTO user_keys (account_id, service, key_name, key_material) VALUES ($1, 'sync', 'key', 'material')").bind(account.id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_codes (code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at) VALUES ($1, $2, $3, 'https://example.test/callback', 'openid', 'challenge', NOW() + INTERVAL '1 hour')")
        .bind(account.id.to_string()).bind(grant.client_id).bind(account.id).execute(pool).await.unwrap();
    let refresh = format!("refresh-{}", account.id);
    sqlx::query("INSERT INTO oauth_refresh_tokens (grant_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 day')")
        .bind(grant.id).bind(Sha256::digest(refresh.as_bytes()).to_vec()).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO used_refresh_tokens (token_hash, grant_id) VALUES ($1, $2)")
        .bind(account.id.as_bytes().as_slice())
        .bind(grant.id)
        .execute(pool)
        .await
        .unwrap();
    app.storage
        .store_recovery_blob(account.id, b"recovery")
        .await
        .unwrap();
    app.storage
        .install_consent_key_bundle(
            grant.id,
            &[2; 41],
            &json!({"kty": "EC"}),
            "encrypted-keypair",
            0,
        )
        .await
        .unwrap();
    refresh
}

#[tokio::test]
async fn deletion_cascades_account_data_preserves_other_accounts_and_rejects_old_sessions() {
    let Some(app) = test_app().await else {
        return;
    };
    let client_id = client(&app).await;
    let (alice, alice_grant) = account(&app, client_id, "alice").await;
    let (bob, bob_grant) = account(&app, client_id, "bob").await;
    let refresh = populate_dependents(&app, &alice, &alice_grant).await;
    populate_dependents(&app, &bob, &bob_grant).await;
    let token = app.auth_token(&alice.id.to_string());
    let oauth = app
        .jwt
        .create_oauth_access_token(claims(&alice, &alice_grant))
        .unwrap();
    for invalid in [None, Some("invalid"), Some(oauth.as_str())] {
        assert_eq!(delete(&app, invalid).await, StatusCode::UNAUTHORIZED);
        assert!(app.storage.get_account_by_id(alice.id).await.is_ok());
    }
    assert_eq!(delete(&app, Some(&token)).await, StatusCode::NO_CONTENT);
    assert!(matches!(
        app.storage.get_account_by_id(alice.id).await,
        Err(StorageError::AccountNotFound)
    ));
    for (table, column, deleted, preserved) in [
        ("registration_states", "account_id", alice.id, bob.id),
        ("login_states", "account_id", alice.id, bob.id),
        ("user_keys", "account_id", alice.id, bob.id),
        ("oauth_codes", "account_id", alice.id, bob.id),
        ("oauth_grants", "account_id", alice.id, bob.id),
        ("recovery_blobs", "account_id", alice.id, bob.id),
        (
            "oauth_refresh_tokens",
            "grant_id",
            alice_grant.id,
            bob_grant.id,
        ),
        (
            "used_refresh_tokens",
            "grant_id",
            alice_grant.id,
            bob_grant.id,
        ),
    ] {
        for (id, expected) in [(deleted, 0_i64), (preserved, 1)] {
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = $1"))
                    .bind(id)
                    .fetch_one(app.storage.pool())
                    .await
                    .unwrap();
            assert_eq!(count, expected, "{table}");
        }
    }
    assert!(app.storage.get_oauth_client(client_id).await.is_ok());
    assert_eq!(
        get_json(
            &app,
            "/v1/auth/validate",
            Some(&app.auth_token(&bob.id.to_string()))
        )
        .await
        .0,
        StatusCode::OK
    );
    for uri in [
        "/v1/auth/validate",
        "/v1/keys",
        "/v1/accounts/root-key",
        &format!("/oauth/grant-keypair?client_id={client_id}"),
    ] {
        assert_eq!(
            get_json(&app, uri, Some(&token)).await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
    assert_eq!(delete(&app, Some(&token)).await, StatusCode::UNAUTHORIZED);
    let (status, body) = post_form(
        &app,
        "/oauth/token",
        None,
        &format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        get_json(&app, "/oauth/userinfo", Some(&oauth)).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post_json(
            &app,
            "/oauth/mailbox",
            Some(&oauth),
            &json!({"mailbox_id": "a".repeat(64)})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // Reusing the same username and email creates a different identity; old tokens stay invalid.
    let replacement = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", &alice.email)
        .await
        .unwrap();
    assert_ne!(replacement.id, alice.id);
    assert_eq!(
        get_json(&app, "/v1/auth/validate", Some(&token)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn deletion_failure_rolls_back_cascades_and_preserves_session() {
    let Some(app) = test_app().await else {
        return;
    };
    let (account, grant) = account(&app, client(&app).await, "alice").await;
    populate_dependents(&app, &account, &grant).await;
    // A dependent record that refuses deletion simulates failure partway through cascading.
    sqlx::raw_sql("CREATE FUNCTION reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected delete failure'; END $$; CREATE TRIGGER reject_delete BEFORE DELETE ON recovery_blobs FOR EACH ROW EXECUTE FUNCTION reject_delete();")
        .execute(app.storage.pool()).await.unwrap();
    let token = app.auth_token(&account.id.to_string());
    assert_eq!(
        delete(&app, Some(&token)).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(app.storage.get_account_by_id(account.id).await.is_ok());
    assert!(app.storage.get_oauth_grant(grant.id).await.is_ok());
    assert_eq!(
        get_json(&app, "/v1/auth/validate", Some(&token)).await.0,
        StatusCode::OK
    );
    for table in [
        "registration_states",
        "login_states",
        "user_keys",
        "oauth_codes",
        "oauth_grants",
        "oauth_refresh_tokens",
        "used_refresh_tokens",
        "recovery_blobs",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(app.storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "{table}");
    }
}

#[tokio::test]
async fn grant_keypair_is_scoped_to_account_and_client_and_handles_first_consent() {
    let Some(app) = test_app().await else {
        return;
    };
    let client_id = client(&app).await;
    let (alice, grant) = account(&app, client_id, "alice").await;
    let (bob, _) = account(&app, client_id, "bob").await;
    let uri = format!("/oauth/grant-keypair?client_id={client_id}");
    let alice_token = app.auth_token(&alice.id.to_string());
    let oauth = app
        .jwt
        .create_oauth_access_token(claims(&alice, &grant))
        .unwrap();
    for token in [None, Some("invalid"), Some(oauth.as_str())] {
        assert_eq!(
            get_json(&app, &uri, token).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for uri in [
        "/oauth/grant-keypair",
        "/oauth/grant-keypair?client_id=",
        "/oauth/grant-keypair?client_id=invalid",
    ] {
        assert_eq!(
            get_json(&app, uri, Some(&alice_token)).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, empty) = get_json(&app, &uri, Some(&alice_token)).await;
    assert_eq!(empty["app_keypair_blob"], "");
    assert!(empty["wrapped_scoped_key"].is_null());
    app.storage
        .install_consent_key_bundle(
            grant.id,
            &[7; 41],
            &json!({"kty": "EC"}),
            "alice-private-bundle",
            0,
        )
        .await
        .unwrap();
    let (status, bundle) = get_json(&app, &uri, Some(&alice_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bundle["app_keypair_blob"], "alice-private-bundle");
    assert_eq!(bundle["wrapped_scoped_key"], B64.encode([7; 41]));
    for (uri, token) in [
        (uri.clone(), app.auth_token(&bob.id.to_string())),
        (
            format!("/oauth/grant-keypair?client_id={}", Uuid::new_v4()),
            alice_token.clone(),
        ),
    ] {
        let (status, body) = get_json(&app, &uri, Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, empty);
    }
    sqlx::query("ALTER TABLE oauth_grants RENAME TO unavailable_grants")
        .execute(app.storage.pool())
        .await
        .unwrap();
    let (status, body) = get_json(&app, &uri, Some(&alice_token)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"error": "internal server error"}));
}

#[tokio::test]
async fn mailbox_validates_input_and_token_binding_before_writing() {
    let Some(app) = test_app().await else {
        return;
    };
    let (alice, grant) = account(&app, client(&app).await, "alice").await;
    let (bob, foreign) = account(&app, client(&app).await, "bob").await;
    let valid = claims(&alice, &grant);
    let token = app.jwt.create_oauth_access_token(valid.clone()).unwrap();
    for id in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
        format!("{} ", "a".repeat(63)),
    ] {
        assert_eq!(
            post_json(
                &app,
                "/oauth/mailbox",
                Some(&token),
                &json!({"mailbox_id": id})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let body = json!({"mailbox_id": "a".repeat(64)});
    for token in [
        None,
        Some("invalid".into()),
        Some(app.auth_token(&alice.id.to_string())),
    ] {
        assert_eq!(
            post_json(&app, "/oauth/mailbox", token.as_deref(), &body)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    for defect in [
        "missing-grant",
        "invalid-grant",
        "foreign-grant",
        "subject",
        "client",
        "invalid-subject",
        "invalid-client",
    ] {
        let mut invalid = valid.clone();
        match defect {
            "missing-grant" => invalid.grant_id = Uuid::new_v4().to_string(),
            "invalid-grant" => invalid.grant_id = "invalid".into(),
            "foreign-grant" => invalid.grant_id = foreign.id.to_string(),
            "subject" => invalid.sub = bob.id.to_string(),
            "invalid-subject" => invalid.sub = "invalid".into(),
            "invalid-client" => {
                invalid.client_id = "invalid".into();
                invalid.aud = vec![invalid.client_id.clone()];
            }
            "client" => {
                invalid.client_id = foreign.client_id.to_string();
                invalid.aud = vec![invalid.client_id.clone()];
            }
            _ => unreachable!(),
        }
        let invalid = app.jwt.create_oauth_access_token(invalid).unwrap();
        assert_eq!(
            post_json(&app, "/oauth/mailbox", Some(&invalid), &body)
                .await
                .0,
            StatusCode::UNAUTHORIZED,
            "{defect}"
        );
        assert!(app
            .storage
            .get_oauth_grant(grant.id)
            .await
            .unwrap()
            .mailbox_id
            .is_none());
        assert!(app
            .storage
            .get_oauth_grant(foreign.id)
            .await
            .unwrap()
            .mailbox_id
            .is_none());
    }
    assert_eq!(
        post_json(&app, "/oauth/mailbox", Some(&token), &body)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn mailbox_first_write_wins_and_duplicate_ids_are_conflicts() {
    let Some(app) = test_app().await else {
        return;
    };
    let (alice, grant) = account(&app, client(&app).await, "alice").await;
    let (bob, foreign) = account(&app, client(&app).await, "bob").await;
    let alice_token = app
        .jwt
        .create_oauth_access_token(claims(&alice, &grant))
        .unwrap();
    let bob_token = app
        .jwt
        .create_oauth_access_token(claims(&bob, &foreign))
        .unwrap();
    for mailbox in ["a", "a", "b"] {
        assert_eq!(
            post_json(
                &app,
                "/oauth/mailbox",
                Some(&alice_token),
                &json!({"mailbox_id": mailbox.repeat(64)})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.storage
                .get_oauth_grant(grant.id)
                .await
                .unwrap()
                .mailbox_id,
            Some("a".repeat(64))
        );
    }
    let (status, body) = post_json(
        &app,
        "/oauth/mailbox",
        Some(&bob_token),
        &json!({"mailbox_id": "a".repeat(64)}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "mailbox_id conflict"}));
    assert!(app
        .storage
        .get_oauth_grant(foreign.id)
        .await
        .unwrap()
        .mailbox_id
        .is_none());
}

#[tokio::test]
async fn concurrent_mailbox_writes_preserve_one_id_per_grant_and_unique_ownership() {
    let Some(app) = test_app().await else {
        return;
    };
    let (alice, grant) = account(&app, client(&app).await, "alice").await;
    let token = app
        .jwt
        .create_oauth_access_token(claims(&alice, &grant))
        .unwrap();
    let first = json!({"mailbox_id": "a".repeat(64)});
    let second = json!({"mailbox_id": "b".repeat(64)});
    let (a, b) = tokio::join!(
        post_json(&app, "/oauth/mailbox", Some(&token), &first),
        post_json(&app, "/oauth/mailbox", Some(&token), &second)
    );
    assert_eq!(a.0, StatusCode::NO_CONTENT);
    assert_eq!(b.0, StatusCode::NO_CONTENT);
    let winner = app
        .storage
        .get_oauth_grant(grant.id)
        .await
        .unwrap()
        .mailbox_id
        .unwrap();
    assert!(["a".repeat(64), "b".repeat(64)].contains(&winner));
    let (bob, bob_grant) = account(&app, client(&app).await, "bob").await;
    let (eve, eve_grant) = account(&app, client(&app).await, "eve").await;
    let bob_token = app
        .jwt
        .create_oauth_access_token(claims(&bob, &bob_grant))
        .unwrap();
    let eve_token = app
        .jwt
        .create_oauth_access_token(claims(&eve, &eve_grant))
        .unwrap();
    let shared = json!({"mailbox_id": "c".repeat(64)});
    let (b, e) = tokio::join!(
        post_json(&app, "/oauth/mailbox", Some(&bob_token), &shared),
        post_json(&app, "/oauth/mailbox", Some(&eve_token), &shared)
    );
    assert!(matches!(
        (b.0, e.0),
        (StatusCode::NO_CONTENT, StatusCode::CONFLICT)
            | (StatusCode::CONFLICT, StatusCode::NO_CONTENT)
    ));
    let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_grants WHERE mailbox_id = $1")
        .bind("c".repeat(64))
        .fetch_one(app.storage.pool())
        .await
        .unwrap();
    assert_eq!(owners, 1);
    assert_eq!(
        app.storage
            .get_oauth_grant(grant.id)
            .await
            .unwrap()
            .mailbox_id,
        Some(winner)
    );
}

#[tokio::test]
async fn deletion_racing_mailbox_registration_cannot_report_a_write_to_a_deleted_grant() {
    use sqlx::Connection;
    use std::{sync::Arc, time::Duration};
    let Some(app) = test_app().await else {
        return;
    };
    let app = Arc::new(app);
    let (alice, grant) = account(&app, client(&app).await, "alice").await;
    let auth_token = app.auth_token(&alice.id.to_string());
    let access_token = app
        .jwt
        .create_oauth_access_token(claims(&alice, &grant))
        .unwrap();
    let mut connection = sqlx::PgConnection::connect_with(&app.storage.pool().connect_options())
        .await
        .unwrap();
    let mut blocker = connection.begin().await.unwrap();
    sqlx::query("SELECT id FROM oauth_grants WHERE id = $1 FOR UPDATE")
        .bind(grant.id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let deleting = app.clone();
    let deletion = tokio::spawn(async move { delete(&deleting, Some(&auth_token)).await });
    async fn wait_for_grant_waiters(connection: &mut sqlx::PgConnection, count: i64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT pid) FROM pg_locks WHERE NOT granted AND pid IN (SELECT pid FROM pg_locks WHERE relation = 'oauth_grants'::regclass)")
                    .fetch_one(&mut *connection).await.unwrap();
                if waiting >= count { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("requests must reach the blocked grant row");
    }
    wait_for_grant_waiters(&mut blocker, 1).await;
    let registering = app.clone();
    let mailbox = tokio::spawn(async move {
        post_json(
            &registering,
            "/oauth/mailbox",
            Some(&access_token),
            &json!({"mailbox_id": "a".repeat(64)}),
        )
        .await
        .0
    });
    wait_for_grant_waiters(&mut blocker, 2).await;
    blocker.commit().await.unwrap();
    assert_eq!(deletion.await.unwrap(), StatusCode::NO_CONTENT);
    assert_eq!(mailbox.await.unwrap(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        app.storage.get_oauth_grant(grant.id).await,
        Err(StorageError::OAuthGrantNotFound)
    ));
}

#[tokio::test]
async fn mailbox_database_failures_are_sanitized_and_leave_the_grant_unmodified() {
    let Some(app) = test_app().await else {
        return;
    };
    let (alice, grant) = account(&app, client(&app).await, "alice").await;
    let token = app
        .jwt
        .create_oauth_access_token(claims(&alice, &grant))
        .unwrap();
    sqlx::query(
        "ALTER TABLE oauth_grants ADD CONSTRAINT reject_mailbox CHECK (mailbox_id IS NULL)",
    )
    .execute(app.storage.pool())
    .await
    .unwrap();
    let (status, body) = post_json(
        &app,
        "/oauth/mailbox",
        Some(&token),
        &json!({"mailbox_id": "a".repeat(64)}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"error": "internal server error"}));
    assert!(app
        .storage
        .get_oauth_grant(grant.id)
        .await
        .unwrap()
        .mailbox_id
        .is_none());
}
