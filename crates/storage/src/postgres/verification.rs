use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

use crate::{
    ConsumeVerificationCode, StorageError, VerificationCode, VerificationStorage,
    VerificationTokenStorage,
};

use super::{rate_limit_key, PostgresStorage};

/// Maximum verification code attempts before lockout.
const MAX_ATTEMPTS: i32 = 5;

struct VerificationCodeRow {
    id: Uuid,
    email: String,
    code_hash: Vec<u8>,
    purpose: String,
    attempts: i32,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<VerificationCodeRow> for VerificationCode {
    fn from(r: VerificationCodeRow) -> Self {
        VerificationCode {
            id: r.id,
            email: r.email,
            code_hash: r.code_hash,
            purpose: r.purpose,
            attempts: r.attempts,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

#[async_trait]
impl VerificationStorage for PostgresStorage {
    async fn create_verification_code(&self, code: &VerificationCode) -> Result<(), StorageError> {
        // Delete any existing codes for this email+purpose before inserting
        sqlx::query!(
            "DELETE FROM email_verification_codes WHERE email = $1 AND purpose = $2",
            code.email,
            code.purpose,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        sqlx::query!(
            r#"
            INSERT INTO email_verification_codes
                (id, email, code_hash, purpose, attempts, created_at, expires_at)
            VALUES ($1, $2, $3, $4, 0, $5, $6)
            "#,
            code.id,
            code.email,
            code.code_hash.as_slice(),
            code.purpose,
            code.created_at,
            code.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_latest_verification_code_by_email(
        &self,
        email: &str,
        purpose: &str,
    ) -> Result<VerificationCode, StorageError> {
        let now = Utc::now();
        let row = sqlx::query_as!(
            VerificationCodeRow,
            r#"
            SELECT id, email, code_hash, purpose, attempts, created_at, expires_at
            FROM email_verification_codes
            WHERE email = $1 AND purpose = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            email,
            purpose,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::VerificationCodeNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::VerificationCodeExpired);
        }
        if row.attempts >= MAX_ATTEMPTS {
            return Err(StorageError::VerificationMaxAttempts);
        }
        Ok(row.into())
    }

    async fn increment_verification_attempts(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE email_verification_codes SET attempts = attempts + 1 WHERE id = $1",
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn consume_verification_code(
        &self,
        email: &str,
        purpose: &str,
        code_hash: &[u8],
        max_attempts: i32,
    ) -> Result<ConsumeVerificationCode, StorageError> {
        // AUD-014: read/increment/delete run in one transaction with the
        // row locked, so concurrent verifications serialize on the lock
        // instead of racing on a stale snapshot (duplicate successes and
        // attempt-bound overruns were both demonstrated against the
        // per-statement implementation).
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let row = sqlx::query_as!(
            VerificationCodeRow,
            r#"
            SELECT id, email, code_hash, purpose, attempts, created_at, expires_at
            FROM email_verification_codes
            WHERE email = $1 AND purpose = $2
            ORDER BY created_at DESC
            LIMIT 1
            FOR UPDATE
            "#,
            email,
            purpose,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        let Some(row) = row else {
            tx.rollback().await.map_err(StorageError::from)?;
            return Err(StorageError::VerificationCodeNotFound);
        };
        if row.expires_at < Utc::now() {
            tx.rollback().await.map_err(StorageError::from)?;
            return Err(StorageError::VerificationCodeExpired);
        }

        if row.attempts >= max_attempts {
            sqlx::query!("DELETE FROM email_verification_codes WHERE id = $1", row.id)
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;
            tx.commit().await.map_err(StorageError::from)?;
            return Ok(ConsumeVerificationCode::Exhausted);
        }

        // Count the attempt before comparing (timing-attack posture of the
        // original flow is preserved: the hash comparison cost is constant
        // either way, but attempts are committed regardless of outcome).
        sqlx::query!(
            "UPDATE email_verification_codes SET attempts = attempts + 1 WHERE id = $1",
            row.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        if !constant_time_eq(code_hash, &row.code_hash) {
            if row.attempts + 1 >= max_attempts {
                sqlx::query!("DELETE FROM email_verification_codes WHERE id = $1", row.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StorageError::from)?;
            }
            tx.commit().await.map_err(StorageError::from)?;
            return Ok(ConsumeVerificationCode::Mismatch);
        }

        sqlx::query!("DELETE FROM email_verification_codes WHERE id = $1", row.id)
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
        Ok(ConsumeVerificationCode::Consumed(row.id))
    }

    async fn delete_verification_code(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM email_verification_codes WHERE id = $1", id,)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn check_and_increment_send_rate(
        &self,
        email: &str,
        max_sends: i32,
        window: Duration,
        identity_hash_key: &[u8],
    ) -> Result<(), StorageError> {
        // HMAC-hash the email to avoid storing plaintext PII in the rate limit table
        let key = rate_limit_key(email, identity_hash_key);
        let window_secs = window.as_secs() as i64;

        // Atomic upsert + check in a single statement. The UPSERT atomically
        // increments send_count (or resets if the window has elapsed), and we
        // check the result. No rollback needed — the count may exceed max_sends
        // slightly under concurrency, but all over-limit requests are rejected.
        let row = sqlx::query!(
            r#"
            INSERT INTO email_verification_rate_limits (identity_key, send_count, window_start)
            VALUES ($1, 1, NOW())
            ON CONFLICT (identity_key) DO UPDATE
            SET send_count   = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - email_verification_rate_limits.window_start))::bigint >= $2
                     THEN 1
                ELSE email_verification_rate_limits.send_count + 1
                END,
                window_start = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - email_verification_rate_limits.window_start))::bigint >= $2
                     THEN NOW()
                ELSE email_verification_rate_limits.window_start
                END
            RETURNING send_count
            "#,
            key,
            window_secs,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if row.send_count > max_sends {
            return Err(StorageError::VerificationRateLimited);
        }
        Ok(())
    }
}

#[async_trait]
impl VerificationTokenStorage for PostgresStorage {
    async fn consume_verification_token(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let result = sqlx::query!(
            r#"
            INSERT INTO used_verification_tokens (jti, expires_at)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            RETURNING jti
            "#,
            jti,
            expires_at,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?;

        // If no row was returned, the JTI already existed (already consumed)
        if result.is_none() {
            return Err(StorageError::VerificationTokenUsed);
        }
        Ok(())
    }
}

/// Length-safe constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
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
}
