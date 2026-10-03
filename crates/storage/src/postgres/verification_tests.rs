use chrono::Duration as TimeDelta;
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

use super::super::test_support::*;
use crate::VerificationCode;

// Schema CHECK constrains purpose to ('registration', 'recovery').
const PURPOSE: &str = "registration";

fn code(created_at: DateTime<Utc>) -> VerificationCode {
    VerificationCode {
        id: Uuid::new_v4(),
        email: TEST_EMAIL.to_owned(),
        code_hash: vec![0x42; 32],
        purpose: PURPOSE.to_owned(),
        // Ignored by the INSERT, which always starts codes at zero attempts.
        attempts: 0,
        created_at,
        expires_at: created_at + TimeDelta::minutes(15),
    }
}

#[tokio::test]
async fn create_then_get_verification_code_roundtrip() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");

    let fetched = storage
        .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
        .await
        .expect("get latest code");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.attempts, 0);
}

#[tokio::test]
async fn create_replaces_existing_code_for_same_email_and_purpose() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage
        .create_verification_code(&code(Utc::now()))
        .await
        .expect("create first code");
    let replacement = code(Utc::now());
    storage
        .create_verification_code(&replacement)
        .await
        .expect("create replacement code");

    let fetched = storage
        .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
        .await
        .expect("get latest code");
    assert_eq!(fetched.id, replacement.id);
}

#[tokio::test]
async fn expired_verification_code_returns_expired() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let mut expired = code(Utc::now());
    expired.expires_at = Utc::now() - TimeDelta::seconds(1);
    storage
        .create_verification_code(&expired)
        .await
        .expect("create expired code");

    assert!(matches!(
        storage
            .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
            .await
            .unwrap_err(),
        StorageError::VerificationCodeExpired
    ));
}

#[tokio::test]
async fn exhausted_verification_code_returns_max_attempts() {
    let Some(storage) = test_storage().await else {
        return;
    };
    // Codes are always created with attempts = 0; lockout comes from
    // repeated increment_verification_attempts calls.
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");
    for _ in 0..5 {
        storage
            .increment_verification_attempts(created.id)
            .await
            .expect("increment attempts");
    }

    assert!(matches!(
        storage
            .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
            .await
            .unwrap_err(),
        StorageError::VerificationMaxAttempts
    ));
}

#[tokio::test]
async fn increment_attempts_persists() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");
    storage
        .increment_verification_attempts(created.id)
        .await
        .expect("increment attempts");

    let fetched = storage
        .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
        .await
        .expect("get code");
    assert_eq!(fetched.attempts, 1);
}

#[tokio::test]
async fn delete_verification_code_removes_it() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");
    storage
        .delete_verification_code(created.id)
        .await
        .expect("delete code");

    assert!(matches!(
        storage
            .get_latest_verification_code_by_email(TEST_EMAIL, PURPOSE)
            .await
            .unwrap_err(),
        StorageError::VerificationCodeNotFound
    ));
}

#[tokio::test]
async fn send_rate_limit_rejects_past_the_cap() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let key = vec![0x11; 32];
    let window = Duration::from_secs(600);

    for _ in 0..2 {
        storage
            .check_and_increment_send_rate(TEST_EMAIL, 2, window, &key)
            .await
            .expect("within send cap");
    }
    assert!(matches!(
        storage
            .check_and_increment_send_rate(TEST_EMAIL, 2, window, &key)
            .await
            .unwrap_err(),
        StorageError::VerificationRateLimited
    ));
}

#[tokio::test]
async fn consume_verification_token_is_single_use() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let jti = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + TimeDelta::minutes(15);

    storage
        .consume_verification_token(&jti, expires_at)
        .await
        .expect("first consume");
    assert!(matches!(
        storage
            .consume_verification_token(&jti, expires_at)
            .await
            .unwrap_err(),
        StorageError::VerificationTokenUsed
    ));
}

// ── Atomic consume (AUD-014) ─────────────────────────────────────────

#[tokio::test]
async fn consume_succeeds_exactly_once_then_row_is_gone() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");

    let outcome = storage
        .consume_verification_code(TEST_EMAIL, PURPOSE, &[0x42; 32], 5)
        .await
        .expect("consume");
    assert_eq!(
        outcome,
        crate::ConsumeVerificationCode::Consumed(created.id)
    );

    // Row deleted: a second presentation of the same (correct) code fails.
    assert!(matches!(
        storage
            .consume_verification_code(TEST_EMAIL, PURPOSE, &[0x42; 32], 5)
            .await
            .unwrap_err(),
        StorageError::VerificationCodeNotFound
    ));
}

#[tokio::test]
async fn concurrent_correct_codes_produce_exactly_one_success() {
    // AUD-014 reproduction: the audit demonstrated two concurrent
    // verifications of one code BOTH succeeding against the
    // per-statement implementation. Under the row-locked consume the
    // second must fail.
    let Some(storage) = test_storage().await else {
        return;
    };
    storage
        .create_verification_code(&code(Utc::now()))
        .await
        .expect("create code");

    let (a, b) = tokio::join!(
        storage.consume_verification_code(TEST_EMAIL, PURPOSE, &[0x42; 32], 5),
        storage.consume_verification_code(TEST_EMAIL, PURPOSE, &[0x42; 32], 5),
    );
    let consumed = usize::from(a.is_ok()) + usize::from(b.is_ok());
    assert_eq!(consumed, 1, "exactly one concurrent consume may succeed");
}

#[tokio::test]
async fn concurrent_wrong_codes_cannot_exceed_the_attempt_bound() {
    // AUD-014 reproduction: the attempt bound could be overrun under
    // concurrency. Six concurrent wrong guesses must produce exactly
    // five counted attempts (the sixth finds the row deleted).
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");

    let wrong = &[0x00; 32];
    let mut joins = Vec::new();
    for _ in 0..6 {
        joins.push(storage.consume_verification_code(TEST_EMAIL, PURPOSE, wrong, 5));
    }
    let results = futures::future::join_all(joins).await;

    let mismatches = results
        .iter()
        .filter(|r| matches!(r, Ok(crate::ConsumeVerificationCode::Mismatch)))
        .count();
    let errors = results.iter().filter(|r| r.is_err()).count();
    assert_eq!(mismatches, 5, "at most max_attempts comparisons may happen");
    assert_eq!(errors, 1, "the sixth guess finds the row consumed");
}

#[tokio::test]
async fn consume_reports_exhausted_without_comparing() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = code(Utc::now());
    storage
        .create_verification_code(&created)
        .await
        .expect("create code");
    for _ in 0..5 {
        storage
            .increment_verification_attempts(created.id)
            .await
            .expect("increment attempts");
    }

    // Even the CORRECT hash must not succeed past the bound.
    let outcome = storage
        .consume_verification_code(TEST_EMAIL, PURPOSE, &[0x42; 32], 5)
        .await
        .expect("consume outcome");
    assert_eq!(outcome, crate::ConsumeVerificationCode::Exhausted);
}
