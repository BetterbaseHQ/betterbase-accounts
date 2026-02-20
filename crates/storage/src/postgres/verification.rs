use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

use crate::{StorageError, VerificationCode, VerificationStorage, VerificationTokenStorage};

use super::PostgresStorage;

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
        _identity_hash_key: &[u8],
    ) -> Result<(), StorageError> {
        let window_secs = window.as_secs() as i64;

        // Use a single upsert + check query
        let row = sqlx::query!(
            r#"
            INSERT INTO email_verification_rate_limits (email, send_count, window_start)
            VALUES ($1, 1, NOW())
            ON CONFLICT (email) DO UPDATE
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
            email,
            window_secs,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if row.send_count > max_sends {
            // Roll back the increment
            sqlx::query!(
                "UPDATE email_verification_rate_limits SET send_count = send_count - 1 WHERE email = $1",
                email,
            )
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
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
