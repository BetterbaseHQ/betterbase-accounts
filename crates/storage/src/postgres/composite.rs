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

        // AUD-009 review: the wrapped root changes here (password change /
        // recovery re-wrap), so the root key version must advance — a
        // rotation prepared against the previous snapshot must not be able
        // to commit its older wrapped root over this write afterwards.
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_record = $2, wrapped_root_key = $3,
                root_key_version = root_key_version + 1, updated_at = NOW()
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

    async fn update_credentials_and_revoke_sessions(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: Option<&[u8]>,
        expected_credentials_version: i64,
        expected_root_key_version: i64,
        recovery_blob: Option<&[u8]>,
    ) -> Result<i64, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        // Serialize against both credential replacement and root rotation. A
        // credential-only fence would let an old re-wrap strand grant keys
        // after a concurrent root rotation.
        let snapshot = sqlx::query!(
            "SELECT credentials_version, root_key_version FROM accounts WHERE id = $1 FOR UPDATE",
            account_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;
        if i64::from(snapshot.credentials_version) != expected_credentials_version {
            return Err(StorageError::CredentialsVersionConflict);
        }
        if i64::from(snapshot.root_key_version) != expected_root_key_version {
            return Err(StorageError::RootKeyVersionConflict);
        }
        let new_version = sqlx::query_scalar!(
            r#"
            UPDATE accounts
            SET opaque_record = $2,
                wrapped_root_key = COALESCE($3, wrapped_root_key),
                credentials_version = credentials_version + 1,
                root_key_version = root_key_version + CASE WHEN $3::bytea IS NULL THEN 0 ELSE 1 END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING credentials_version
            "#,
            account_id,
            opaque_record,
            wrapped_root_key,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .map(i64::from)
        .ok_or(StorageError::AccountNotFound)?;
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id IN (SELECT id FROM oauth_grants WHERE account_id = $1)",
            account_id
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        if let Some(blob) = recovery_blob {
            sqlx::query!(
                r#"
                INSERT INTO recovery_blobs (account_id, blob)
                VALUES ($1, $2)
                ON CONFLICT (account_id) DO UPDATE SET blob = EXCLUDED.blob
                "#,
                account_id,
                blob,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }
        tx.commit().await.map_err(StorageError::from)?;
        Ok(new_version)
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

        // AUD-009 review: row locks do not cover rows that do not exist
        // yet, and PostgreSQL has no predicate locking under READ
        // COMMITTED. Locking the account row serializes this rotation
        // against grant creation (get_or_create_oauth_grant takes the
        // same lock), so a new grant cannot slip between the completeness
        // check and the commit.
        let locked = sqlx::query_scalar!(
            "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        if locked.is_none() {
            return Err(StorageError::AccountNotFound);
        }

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

#[cfg(test)]
mod tests {
    use super::super::test_support::{create_account, test_storage};
    use super::*;
    use crate::{
        AccountStorage, OAuthClient, OAuthClientStorage, OAuthGrantStorage, OAuthRefreshToken,
        OAuthRefreshTokenStorage, RecoveryStorage, RootKeyStorage,
    };

    async fn seed_refresh_token(storage: &PostgresStorage, account_id: Uuid) -> Vec<u8> {
        let client_id = Uuid::new_v4();
        storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "test".into(),
                secret_hash: None,
                redirect_uris: vec!["https://example.test/callback".into()],
                allowed_scopes: vec!["openid".into()],
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let grant = storage
            .get_or_create_oauth_grant(client_id, account_id, "openid")
            .await
            .unwrap();
        let hash = vec![42; 32];
        storage
            .create_refresh_token(&OAuthRefreshToken {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                token_hash: hash.clone(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            })
            .await
            .unwrap();
        hash
    }

    #[tokio::test]
    async fn credential_update_revokes_sessions_with_or_without_a_new_root_key() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        storage
            .finalize_registration_with_root_key(account.id, b"original", &[1; 41])
            .await
            .unwrap();
        for (expected, key) in [None, Some([2; 41].as_slice())].into_iter().enumerate() {
            let hash = seed_refresh_token(&storage, account.id).await;
            let version = storage
                .update_credentials_and_revoke_sessions(
                    account.id,
                    b"replacement",
                    key,
                    expected as i64,
                    0,
                    Some(b"new blob"),
                )
                .await
                .unwrap();
            assert_eq!(version, expected as i64 + 1);
            let updated = storage.get_account_by_id(account.id).await.unwrap();
            assert_eq!(updated.credentials_version, version);
            assert_eq!(
                updated.opaque_record.as_deref(),
                Some(b"replacement".as_slice())
            );
            assert_eq!(
                updated.wrapped_root_key,
                Some(vec![if key.is_some() { 2 } else { 1 }; 41])
            );
            assert!(matches!(
                storage.get_refresh_token_by_hash(&hash).await,
                Err(StorageError::RefreshTokenNotFound)
            ));
            assert_eq!(
                storage
                    .get_recovery_blob_by_email(&account.issuer, &account.email)
                    .await
                    .unwrap(),
                b"new blob"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_credential_changes_only_commit_once() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        let (a, b) = tokio::join!(
            storage.update_credentials_and_revoke_sessions(account.id, b"first", None, 0, 0, None),
            storage.update_credentials_and_revoke_sessions(account.id, b"second", None, 0, 0, None),
        );
        assert!(matches!(
            (&a, &b),
            (Ok(1), Err(StorageError::CredentialsVersionConflict))
                | (Err(StorageError::CredentialsVersionConflict), Ok(1))
        ));
        let account = storage.get_account_by_id(account.id).await.unwrap();
        assert_eq!(account.credentials_version, 1);
        assert_eq!(
            account.opaque_record.as_deref(),
            Some(if a.is_ok() {
                b"first".as_slice()
            } else {
                b"second".as_slice()
            })
        );
    }

    #[tokio::test]
    async fn failed_recovery_blob_write_rolls_back_credentials_and_revocation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        storage
            .finalize_registration_with_root_key(account.id, b"original", &[1; 41])
            .await
            .unwrap();
        storage
            .store_recovery_blob(account.id, b"original blob")
            .await
            .unwrap();
        let hash = seed_refresh_token(&storage, account.id).await;
        // Force the final write to fail after the credentials update and token deletion.
        // This constraint exists only in this test's private schema.
        sqlx::query("ALTER TABLE recovery_blobs ADD CONSTRAINT reject_replacement CHECK (blob = decode('6f726967696e616c20626c6f62', 'hex'))")
            .execute(storage.pool()).await.unwrap();
        let error = storage
            .update_credentials_and_revoke_sessions(
                account.id,
                b"replacement",
                Some(&[2; 41]),
                0,
                0,
                Some(b"new blob"),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StorageError::Database(_)));
        let unchanged = storage.get_account_by_id(account.id).await.unwrap();
        assert_eq!(unchanged.credentials_version, 0);
        assert_eq!(
            unchanged.opaque_record.as_deref(),
            Some(b"original".as_slice())
        );
        assert_eq!(unchanged.wrapped_root_key, Some(vec![1; 41]));
        assert_eq!(
            storage
                .get_root_key_with_version(account.id)
                .await
                .unwrap()
                .1,
            0
        );
        assert!(storage.get_refresh_token_by_hash(&hash).await.is_ok());
        assert_eq!(
            storage
                .get_recovery_blob_by_email(&account.issuer, &account.email)
                .await
                .unwrap(),
            b"original blob"
        );
    }
}
