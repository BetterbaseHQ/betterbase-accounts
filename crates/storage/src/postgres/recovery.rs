use async_trait::async_trait;
use uuid::Uuid;

use crate::{RecoveryStorage, StorageError};

use super::PostgresStorage;

#[async_trait]
impl RecoveryStorage for PostgresStorage {
    async fn store_recovery_blob(&self, account_id: Uuid, blob: &[u8]) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO recovery_blobs (account_id, blob)
            VALUES ($1, $2)
            ON CONFLICT (account_id) DO UPDATE SET blob = EXCLUDED.blob
            "#,
            account_id,
            blob,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_recovery_blob_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<Vec<u8>, StorageError> {
        self.get_recovery_blob_with_root_version_by_email(issuer, email)
            .await
            .map(|(blob, _)| blob)
    }

    async fn get_recovery_blob_with_root_version_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<(Vec<u8>, i64), StorageError> {
        let row = sqlx::query!(
            r#"
            SELECT rb.blob, a.root_key_version
            FROM recovery_blobs rb
            JOIN accounts a ON a.id = rb.account_id
            WHERE a.issuer = $1 AND a.email = $2
            "#,
            issuer,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::RecoveryBlobNotFound)?;

        Ok((row.blob, i64::from(row.root_key_version)))
    }

    async fn delete_recovery_blob(&self, account_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!(
            "DELETE FROM recovery_blobs WHERE account_id = $1",
            account_id,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use crate::CompositeStorage;

    #[tokio::test]
    async fn recovery_snapshot_tracks_atomic_root_key_rotation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        storage
            .store_recovery_blob(account.id, b"original blob")
            .await
            .unwrap();
        let original = (b"original blob".to_vec(), 0);
        let replacement = (b"replacement blob".to_vec(), 1);
        assert_eq!(
            storage
                .get_recovery_blob_with_root_version_by_email(TEST_ISSUER, TEST_EMAIL)
                .await
                .unwrap(),
            original
        );
        let (read, rotated) = tokio::join!(
            storage.get_recovery_blob_with_root_version_by_email(TEST_ISSUER, TEST_EMAIL),
            storage.rotate_root_key(account.id, 0, &[2; 41], &[], b"replacement blob"),
        );
        assert_eq!(rotated.unwrap(), 1);
        let read = read.unwrap();
        assert!(read == original || read == replacement);
        assert_eq!(
            storage
                .get_recovery_blob_with_root_version_by_email(TEST_ISSUER, TEST_EMAIL)
                .await
                .unwrap(),
            replacement
        );
    }

    #[tokio::test]
    async fn store_and_fetch_recovery_blob_by_email() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        let blob = vec![0x0A, 0x0B, 0x0C];

        storage
            .store_recovery_blob(account.id, &blob)
            .await
            .expect("store recovery blob");

        let fetched = storage
            .get_recovery_blob_by_email(TEST_ISSUER, TEST_EMAIL)
            .await
            .expect("fetch recovery blob");
        assert_eq!(fetched, blob);
    }

    #[tokio::test]
    async fn store_recovery_blob_overwrites_existing() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        storage
            .store_recovery_blob(account.id, b"first")
            .await
            .expect("store first blob");
        storage
            .store_recovery_blob(account.id, b"second")
            .await
            .expect("store second blob");

        let fetched = storage
            .get_recovery_blob_by_email(TEST_ISSUER, TEST_EMAIL)
            .await
            .expect("fetch recovery blob");
        assert_eq!(fetched, b"second".to_vec());
    }

    #[tokio::test]
    async fn missing_recovery_blob_returns_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        create_account(&storage).await;
        assert!(matches!(
            storage
                .get_recovery_blob_by_email(TEST_ISSUER, TEST_EMAIL)
                .await
                .unwrap_err(),
            StorageError::RecoveryBlobNotFound
        ));
    }

    #[tokio::test]
    async fn delete_recovery_blob_removes_it() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        storage
            .store_recovery_blob(account.id, b"blob")
            .await
            .expect("store recovery blob");
        storage
            .delete_recovery_blob(account.id)
            .await
            .expect("delete recovery blob");

        assert!(matches!(
            storage
                .get_recovery_blob_by_email(TEST_ISSUER, TEST_EMAIL)
                .await
                .unwrap_err(),
            StorageError::RecoveryBlobNotFound
        ));
    }
}
