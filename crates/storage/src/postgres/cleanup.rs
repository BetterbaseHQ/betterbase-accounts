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

    async fn cleanup_unregistered_accounts(
        &self,
        older_than: Duration,
    ) -> Result<(), StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(older_than.as_secs() as i64);
        sqlx::query!(
            "DELETE FROM accounts WHERE opaque_record IS NULL AND created_at < $1",
            cutoff,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::test_support::*;

    use super::*;

    #[tokio::test]
    async fn cleanup_unregistered_accounts_reclaims_only_stale_reservations() {
        let Some(storage) = test_storage().await else {
            return;
        };
        // Abandoned reservation, backdated past the retention window.
        let stale = storage
            .get_or_create_account(TEST_ISSUER, "stale", "stale@example.com")
            .await
            .expect("create stale");
        sqlx::query("UPDATE accounts SET created_at = NOW() - INTERVAL '8 days' WHERE id = $1")
            .bind(stale.id)
            .execute(storage.pool())
            .await
            .expect("backdate");

        // Fresh reservation (still within the funnel) and a registered
        // account. The registered account is backdated TOO — the
        // `opaque_record IS NULL` predicate must be the only thing
        // protecting it, pinning that the cleanup never reaps real accounts.
        let fresh = storage
            .get_or_create_account(TEST_ISSUER, "fresh", "fresh@example.com")
            .await
            .expect("create fresh");
        let registered = create_account(&storage).await;
        storage
            .finalize_registration(registered.id, b"record")
            .await
            .expect("register");
        sqlx::query("UPDATE accounts SET created_at = NOW() - INTERVAL '8 days' WHERE id = $1")
            .bind(registered.id)
            .execute(storage.pool())
            .await
            .expect("backdate registered account past the cutoff");

        storage
            .cleanup_unregistered_accounts(Duration::from_secs(7 * 24 * 3600))
            .await
            .expect("cleanup");

        assert!(matches!(
            storage.get_account_by_id(stale.id).await.unwrap_err(),
            StorageError::AccountNotFound
        ));
        assert!(storage.get_account_by_id(fresh.id).await.is_ok());
        assert!(storage.get_account_by_id(registered.id).await.is_ok());
    }
}
