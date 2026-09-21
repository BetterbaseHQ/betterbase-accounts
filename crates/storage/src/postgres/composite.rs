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
            SET opaque_record = $2, wrapped_root_key = $3
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
        expected_root_version: i64,
        wrapped_root_key: &[u8],
        grant_updates: &[GrantKeyUpdate],
        recovery_blob: &[u8],
    ) -> Result<i64, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        // AUD-009: lock the account's full grant set first so the
        // completeness check below cannot interleave with a concurrent
        // consent writing one of these rows.
        let grant_ids: Vec<Uuid> = sqlx::query_scalar!(
            "SELECT id FROM oauth_grants WHERE account_id = $1 FOR UPDATE",
            account_id
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        // The rotation must cover every grant on the account — committing
        // a partial list would strand the omitted grants under the old
        // root forever (there is no later path that learns the old root).
        let submitted: std::collections::HashSet<Uuid> =
            grant_updates.iter().map(|u| u.grant_id).collect();
        let stored: std::collections::HashSet<Uuid> = grant_ids.iter().copied().collect();
        if submitted != stored {
            return Err(StorageError::RotationGrantsIncomplete);
        }

        // CAS on the root key version: a rotation (or credential change)
        // prepared against an older snapshot must not overwrite the newer
        // state. Returns the new version on success.
        let new_version = sqlx::query_scalar!(
            r#"
            UPDATE accounts
            SET wrapped_root_key = $2,
                root_key_version = root_key_version + 1,
                updated_at = NOW()
            WHERE id = $1 AND root_key_version = $3
            RETURNING root_key_version
            "#,
            account_id,
            wrapped_root_key,
            expected_root_version as i32,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .map(i64::from)
        .ok_or(StorageError::RootKeyVersionConflict)?;

        // Batch update grant wrapped keys
        for update in grant_updates {
            sqlx::query!(
                "UPDATE oauth_grants SET wrapped_scoped_key = $2, updated_at = NOW() WHERE id = $1",
                update.grant_id,
                update.wrapped_scoped_key.as_slice(),
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        // AUD-009 recovery semantics: a rotation with a new blob replaces
        // it; a rotation without one deletes the old blob — the old blob
        // decrypts to the retired root and would present a false recovery
        // path that yields a dead key.
        if recovery_blob.is_empty() {
            sqlx::query!(
                "DELETE FROM recovery_blobs WHERE account_id = $1",
                account_id
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        } else {
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
        Ok(new_version)
    }
}
