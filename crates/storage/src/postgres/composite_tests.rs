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
