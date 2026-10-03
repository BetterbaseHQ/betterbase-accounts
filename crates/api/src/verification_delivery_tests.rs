//! Verification contracts exercised through the router with real storage.
use crate::test_support::{post_json, test_app_with_mailer, TestApp, TEST_ISSUER};
use async_trait::async_trait;
use axum::http::StatusCode;
use betterbase_accounts_email::{EmailError, Mailer, VerificationEmail};
use betterbase_accounts_storage::{AccountStorage, VerificationStorage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
struct RecordingMailer {
    messages: Mutex<Vec<VerificationEmail>>,
    fail: AtomicBool,
}
#[async_trait]
impl Mailer for RecordingMailer {
    async fn send_verification_code(&self, email: &VerificationEmail) -> Result<(), EmailError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EmailError::Send("private SMTP diagnostic".into()));
        }
        self.messages.lock().unwrap().push(email.clone());
        Ok(())
    }
}
impl RecordingMailer {
    fn latest(&self) -> VerificationEmail {
        self.messages.lock().unwrap().last().unwrap().clone()
    }
}
async fn send(app: &TestApp, email: &str, purpose: &str) -> (StatusCode, Value) {
    post_json(
        app,
        "/v1/accounts/verify/send",
        None,
        &json!({"username": "alice", "email": email, "purpose": purpose}),
    )
    .await
}
async fn confirm(app: &TestApp, email: &str, code: &str) -> (StatusCode, Value) {
    post_json(
        app,
        "/v1/accounts/verify/confirm",
        None,
        &json!({"email": email, "purpose": "registration", "code": code}),
    )
    .await
}

#[tokio::test]
async fn send_stores_only_hash_matches_delivered_expiry_and_confirm_is_single_use() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    let (status, body) = send(&app, "Alice.Test+tag@GMAIL.COM", "registration").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let email = mailer.latest();
    assert_eq!(email.to, "alicetest@gmail.com");
    assert_eq!(email.purpose, "registration");
    assert_eq!(email.code.len(), 6);
    assert!(email.code.bytes().all(|c| c.is_ascii_digit()));
    let stored = app
        .storage
        .get_latest_verification_code_by_email(&email.to, "registration")
        .await
        .unwrap();
    assert_eq!(
        stored.code_hash,
        Sha256::digest(email.code.as_bytes()).to_vec()
    );
    assert_eq!((stored.expires_at - stored.created_at).num_seconds(), 600);
    assert_eq!(email.expires_in.as_secs(), 600);
    let (status, body) = confirm(&app, "a.lice.test@gmail.com", &email.code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = app
        .jwt
        .validate_verification_token(body["verification_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.email, email.to);
    assert_eq!(claims.purpose, "registration");
    assert_eq!(
        confirm(&app, &email.to, &email.code).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn resend_replaces_old_record_and_resets_attempts_and_expiry() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    assert_eq!(
        send(&app, "alice@example.test", "registration").await.0,
        StatusCode::NO_CONTENT
    );
    let old = mailer.latest();
    let record = app
        .storage
        .get_latest_verification_code_by_email(&old.to, "registration")
        .await
        .unwrap();
    sqlx::query("UPDATE email_verification_codes SET attempts = 5, expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(record.id).execute(app.storage.pool()).await.unwrap();
    assert_eq!(
        send(&app, &old.to, "registration").await.0,
        StatusCode::NO_CONTENT
    );
    let new = mailer.latest();
    let current = app
        .storage
        .get_latest_verification_code_by_email(&new.to, "registration")
        .await
        .unwrap();
    assert_ne!(current.id, record.id);
    assert_eq!(current.attempts, 0);
    assert!(current.expires_at > chrono::Utc::now());
    // Six-digit codes can legitimately repeat; replacement is always verified
    // by record id above, and an actually different stale code must be rejected.
    if old.code != new.code {
        assert_eq!(
            confirm(&app, &new.to, &old.code).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(confirm(&app, &new.to, &new.code).await.0, StatusCode::OK);
}

#[tokio::test]
async fn invalid_send_requests_do_not_deliver_mail() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    for (email, username, purpose) in [
        ("invalid", "alice", "registration"),
        ("alice@example.test", "!", "registration"),
        ("alice@example.test", "alice", "invalid"),
    ] {
        let (status, _) = post_json(
            &app,
            "/v1/accounts/verify/send",
            None,
            &json!({"email": email, "username": username, "purpose": purpose}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(mailer.messages.lock().unwrap().is_empty());
    assert_eq!(
        send(&app, "alice@example.test", "registration").await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn send_limit_is_shared_across_purposes_and_canonical_email_aliases() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    for n in 0..5 {
        assert_eq!(
            send(
                &app,
                "Alice.Test+tag@gmail.com",
                if n % 2 == 0 {
                    "registration"
                } else {
                    "recovery"
                }
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        send(&app, "alicetest@gmail.com", "registration").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        send(&app, "alicetest@gmail.com", "recovery").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(mailer.messages.lock().unwrap().len(), 5);
    assert_eq!(
        send(&app, "bob@gmail.com", "registration").await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn mailer_failures_are_sanitized_and_recovery_does_not_reveal_account_existence() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    app.storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    mailer.fail.store(true, Ordering::SeqCst);
    let (status, body) = send(&app, "alice@example.test", "registration").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"error": "internal server error"}));
    for failing in [true, false] {
        mailer.fail.store(failing, Ordering::SeqCst);
        let known = send(&app, "alice@example.test", "recovery").await;
        let unknown = send(&app, "missing@example.test", "recovery").await;
        assert_eq!(known, unknown);
        assert_eq!(known, (StatusCode::NO_CONTENT, Value::Null));
    }
    assert_eq!(
        send(&app, "alice@example.test", "registration").await.0,
        StatusCode::NO_CONTENT
    );
    let email = mailer.latest();
    assert_eq!(
        confirm(&app, &email.to, &email.code).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn confirmation_enforces_attempt_limit_and_expiry() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    for (email, wrong_attempts) in [("allowed@example.test", 4), ("locked@example.test", 5)] {
        assert_eq!(
            send(&app, email, "registration").await.0,
            StatusCode::NO_CONTENT
        );
        let message = mailer.latest();
        let wrong = if message.code == "000000" {
            "111111"
        } else {
            "000000"
        };
        for _ in 0..wrong_attempts {
            assert_eq!(confirm(&app, email, wrong).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            confirm(&app, email, &message.code).await.0,
            if wrong_attempts == 4 {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            }
        );
    }
    assert_eq!(
        send(&app, "expired@example.test", "registration").await.0,
        StatusCode::NO_CONTENT
    );
    let message = mailer.latest();
    sqlx::query("UPDATE email_verification_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE email = $1")
        .bind(&message.to).execute(app.storage.pool()).await.unwrap();
    assert_eq!(
        confirm(&app, &message.to, &message.code).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn concurrent_sends_enforce_the_limit_and_the_window_can_reset() {
    let mailer = Arc::new(RecordingMailer::default());
    let Some(app) = test_app_with_mailer(mailer.clone()).await else {
        return;
    };
    let app = Arc::new(app);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = app.clone();
        tasks.spawn(async move { send(&app, "alice@example.test", "registration").await.0 });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            StatusCode::NO_CONTENT => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected status: {other}"),
        }
    }
    assert_eq!(accepted, 5);
    assert_eq!(mailer.messages.lock().unwrap().len(), 5);
    sqlx::query(
        "UPDATE email_verification_rate_limits SET window_start = NOW() - INTERVAL '2 hours'",
    )
    .execute(app.storage.pool())
    .await
    .unwrap();
    assert_eq!(
        send(&app, "alice@example.test", "registration").await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(mailer.messages.lock().unwrap().len(), 6);
}
