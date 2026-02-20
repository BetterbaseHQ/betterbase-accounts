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
        let row = sqlx::query!(
            r#"
            SELECT rb.blob
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

        Ok(row.blob)
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
