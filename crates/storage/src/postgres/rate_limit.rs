use async_trait::async_trait;
use chrono::Utc;
use std::time::Duration;

use crate::{RateLimitStorage, StorageError};

use super::{rate_limit_key, PostgresStorage};

#[async_trait]
impl RateLimitStorage for PostgresStorage {
    async fn check_login_allowed(&self, issuer: &str, username: &str) -> Result<(), StorageError> {
        let now = Utc::now();
        let row = sqlx::query!(
            r#"
            SELECT locked_until
            FROM login_attempts
            WHERE issuer = $1 AND username = $2
            "#,
            issuer,
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if let Some(row) = row {
            if let Some(locked_until) = row.locked_until {
                if locked_until > now {
                    return Err(StorageError::LoginRateLimited);
                }
            }
        }
        Ok(())
    }

    async fn record_failed_login(
        &self,
        issuer: &str,
        username: &str,
        max_attempts: i32,
        window: Duration,
    ) -> Result<Option<Duration>, StorageError> {
        let window_secs = window.as_secs() as i64;

        struct Row {
            failed_count: i32,
            lockout_count: i32,
        }

        let row = sqlx::query_as!(
            Row,
            r#"
            INSERT INTO login_attempts (issuer, username, failed_count, first_failed_at, lockout_count)
            VALUES ($1, $2, 1, NOW(), 0)
            ON CONFLICT (issuer, username) DO UPDATE
            SET failed_count    = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - login_attempts.first_failed_at))::bigint >= $3
                     THEN 1
                ELSE login_attempts.failed_count + 1
                END,
                first_failed_at = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - login_attempts.first_failed_at))::bigint >= $3
                     THEN NOW()
                ELSE login_attempts.first_failed_at
                END
            RETURNING failed_count, lockout_count
            "#,
            issuer,
            username,
            window_secs,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if row.failed_count >= max_attempts {
            // Escalating lockout: 1min, 5min, 15min, 60min, 24h ...
            let lockout_secs = lockout_duration_secs(row.lockout_count);
            let lockout_dur = Duration::from_secs(lockout_secs);
            let locked_until = Utc::now() + chrono::Duration::seconds(lockout_secs as i64);

            sqlx::query!(
                r#"
                UPDATE login_attempts
                SET locked_until  = $3,
                    failed_count  = 0,
                    first_failed_at = NULL,
                    lockout_count = lockout_count + 1
                WHERE issuer = $1 AND username = $2
                "#,
                issuer,
                username,
                locked_until,
            )
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;

            return Ok(Some(lockout_dur));
        }
        Ok(None)
    }

    async fn clear_login_attempts(&self, issuer: &str, username: &str) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            UPDATE login_attempts
            SET failed_count = 0, first_failed_at = NULL, locked_until = NULL
            WHERE issuer = $1 AND username = $2
            "#,
            issuer,
            username,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn check_and_increment_recovery_rate(
        &self,
        email: &str,
        max_requests: i32,
        window: Duration,
        identity_hash_key: &[u8],
    ) -> Result<(), StorageError> {
        let key = rate_limit_key(email, identity_hash_key);
        let window_secs = window.as_secs() as i64;

        let row = sqlx::query!(
            r#"
            INSERT INTO recovery_requests (identity_key, request_count, window_start)
            VALUES ($1, 1, NOW())
            ON CONFLICT (identity_key) DO UPDATE
            SET request_count = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - recovery_requests.window_start))::bigint >= $2
                     THEN 1
                ELSE recovery_requests.request_count + 1
                END,
                window_start  = CASE
                WHEN EXTRACT(EPOCH FROM (NOW() - recovery_requests.window_start))::bigint >= $2
                     THEN NOW()
                ELSE recovery_requests.window_start
                END
            RETURNING request_count
            "#,
            key,
            window_secs,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if row.request_count > max_requests {
            return Err(StorageError::RecoveryRateLimited);
        }
        Ok(())
    }
}

/// Escalating lockout schedule (seconds): 15m, 1h, 24h, 24h, ...
fn lockout_duration_secs(lockout_count: i32) -> u64 {
    match lockout_count {
        0 => 900,
        1 => 3600,
        _ => 86400,
    }
}
