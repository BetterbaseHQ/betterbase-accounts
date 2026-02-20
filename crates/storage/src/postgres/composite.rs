use async_trait::async_trait;
use uuid::Uuid;

use crate::{CompositeStorage, GrantKeyUpdate, StorageError};

use super::PostgresStorage;

#[async_trait]
impl CompositeStorage for PostgresStorage {
    async fn update_registration_and_root_key(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: &[u8],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_registration = $2, wrapped_root_key = $3
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
            wrapped_root_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            tx.rollback().await.map_err(StorageError::from)?;
            return Err(StorageError::AccountNotFound);
        }

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn rotate_root_key(
        &self,
        account_id: Uuid,
        wrapped_root_key: &[u8],
        grant_updates: &[GrantKeyUpdate],
        recovery_blob: &[u8],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        // Update wrapped root key
        sqlx::query!(
            "UPDATE accounts SET wrapped_root_key = $2 WHERE id = $1",
            account_id,
            wrapped_root_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        // Batch update grant wrapped keys
        for update in grant_updates {
            sqlx::query!(
                "UPDATE oauth_grants SET wrapped_scoped_key = $2 WHERE id = $1",
                update.grant_id,
                update.wrapped_scoped_key.as_slice(),
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        // Update recovery blob if non-empty
        if !recovery_blob.is_empty() {
            sqlx::query!(
                r#"
                INSERT INTO recovery_blobs (account_id, blob)
                VALUES ($1, $2)
                ON CONFLICT (account_id) DO UPDATE SET blob = EXCLUDED.blob
                "#,
                account_id,
                recovery_blob,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }
}
