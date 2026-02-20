use async_trait::async_trait;
use std::time::Duration;

use crate::{CleanupStorage, StorageError};

use super::PostgresStorage;

#[async_trait]
impl CleanupStorage for PostgresStorage {
    async fn cleanup_expired_states(&self) -> Result<(), StorageError> {
        let now = chrono::Utc::now();
        sqlx::query!("DELETE FROM registration_states WHERE expires_at < $1", now)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        sqlx::query!("DELETE FROM login_states WHERE expires_at < $1", now)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn cleanup_expired_oauth_codes(&self) -> Result<(), StorageError> {
        let now = chrono::Utc::now();
        sqlx::query!("DELETE FROM oauth_codes WHERE expires_at < $1", now)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn cleanup_expired_refresh_tokens(&self) -> Result<(), StorageError> {
        let now = chrono::Utc::now();
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE expires_at < $1",
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn cleanup_used_refresh_tokens(&self, older_than: Duration) -> Result<(), StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(older_than.as_secs() as i64);
        sqlx::query!("DELETE FROM used_refresh_tokens WHERE used_at < $1", cutoff,)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn cleanup_expired_verification_codes(&self) -> Result<(), StorageError> {
        let now = chrono::Utc::now();
        sqlx::query!(
            "DELETE FROM email_verification_codes WHERE expires_at < $1",
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn cleanup_expired_verification_tokens(&self) -> Result<(), StorageError> {
        let now = chrono::Utc::now();
        sqlx::query!(
            "DELETE FROM used_verification_tokens WHERE expires_at < $1",
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }
}
