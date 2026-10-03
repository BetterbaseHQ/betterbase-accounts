//! Real PostgreSQL interleavings; locks, rather than sleeps, establish ordering.
use super::{test_support::*, PostgresStorage};
use crate::{CompositeStorage, GrantKeyUpdate, OAuthClient, OAuthClientStorage, OAuthGrantStorage};
use sqlx::Connection;
use uuid::Uuid;

async fn client(storage: &PostgresStorage) -> Uuid {
    let id = Uuid::new_v4();
    storage
        .create_oauth_client(&OAuthClient {
            id,
            name: "rotation test".into(),
            secret_hash: None,
            redirect_uris: vec!["https://example.test/callback".into()],
            allowed_scopes: vec!["sync".into()],
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    id
}

async fn wait_for_blocked(connection: &mut sqlx::PgConnection, count: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT pid) FROM pg_locks WHERE NOT granted AND pid IN (SELECT pid FROM pg_locks WHERE relation = 'accounts'::regclass)")
                .fetch_one(&mut *connection).await.unwrap();
            if waiting >= count { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("operations must reach their database locks");
}

#[tokio::test]
async fn rotation_fences_a_concurrent_wrapped_key_update() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    let mut connection = sqlx::PgConnection::connect_with(&storage.pool.connect_options())
        .await
        .unwrap();
    let mut blocker = connection.begin().await.unwrap();
    sqlx::query("SELECT id FROM oauth_grants WHERE id = $1 FOR UPDATE")
        .bind(grant.id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let rotating = storage.clone();
    let rotation = tokio::spawn(async move {
        rotating
            .rotate_root_key(
                account.id,
                0,
                &[2; 41],
                &[GrantKeyUpdate {
                    grant_id: grant.id,
                    wrapped_scoped_key: vec![2; 41],
                }],
                b"new recovery",
            )
            .await
    });
    wait_for_blocked(&mut blocker, 1).await;
    let updating = storage.clone();
    let update = tokio::spawn(async move {
        updating
            .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], 0)
            .await
    });
    wait_for_blocked(&mut blocker, 2).await;
    blocker.commit().await.unwrap();
    assert_eq!(rotation.await.unwrap().unwrap(), 1);
    assert!(
        matches!(
            update.await.unwrap(),
            Err(StorageError::RootKeyVersionConflict)
        ),
        "a wrapper derived under the old root must not overwrite the rotation"
    );
    assert_eq!(
        storage
            .get_oauth_grant(grant.id)
            .await
            .unwrap()
            .wrapped_scoped_key,
        Some(vec![2; 41])
    );
}

#[tokio::test]
async fn concurrent_rotations_commit_one_consistent_bundle() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    let a = [GrantKeyUpdate {
        grant_id: grant.id,
        wrapped_scoped_key: vec![1; 41],
    }];
    let b = [GrantKeyUpdate {
        grant_id: grant.id,
        wrapped_scoped_key: vec![2; 41],
    }];
    let (first, second) = tokio::join!(
        storage.rotate_root_key(account.id, 0, &[1; 41], &a, &[1; 64]),
        storage.rotate_root_key(account.id, 0, &[2; 41], &b, &[2; 64]),
    );
    let winner = match (first, second) {
        (Ok(1), Err(StorageError::RootKeyVersionConflict)) => 1,
        (Err(StorageError::RootKeyVersionConflict), Ok(1)) => 2,
        result => panic!("unexpected rotation results: {result:?}"),
    };
    assert_eq!(
        storage.get_root_key_with_version(account.id).await.unwrap(),
        (vec![winner; 41], 1)
    );
    assert_eq!(
        storage
            .get_oauth_grant(grant.id)
            .await
            .unwrap()
            .wrapped_scoped_key,
        Some(vec![winner; 41])
    );
    assert_eq!(
        storage
            .get_recovery_blob_by_email(&account.issuer, &account.email)
            .await
            .unwrap(),
        vec![winner; 64]
    );
}

#[tokio::test]
async fn failed_rotation_rolls_back_root_grants_and_recovery() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    storage
        .finalize_registration_with_root_key(account.id, b"record", &[1; 41])
        .await
        .unwrap();
    storage
        .store_recovery_blob(account.id, &[1; 64])
        .await
        .unwrap();
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    storage
        .update_grant_wrapped_scoped_key(grant.id, &[1; 41])
        .await
        .unwrap();
    sqlx::query("ALTER TABLE recovery_blobs ADD CONSTRAINT reject_replacement CHECK (get_byte(blob, 0) = 1)").execute(storage.pool()).await.unwrap();
    assert!(storage
        .rotate_root_key(
            account.id,
            0,
            &[2; 41],
            &[GrantKeyUpdate {
                grant_id: grant.id,
                wrapped_scoped_key: vec![2; 41]
            }],
            &[2; 64]
        )
        .await
        .is_err());
    assert_eq!(
        storage.get_root_key_with_version(account.id).await.unwrap(),
        (vec![1; 41], 0)
    );
    assert_eq!(
        storage
            .get_oauth_grant(grant.id)
            .await
            .unwrap()
            .wrapped_scoped_key,
        Some(vec![1; 41])
    );
    assert_eq!(
        storage
            .get_recovery_blob_by_email(&account.issuer, &account.email)
            .await
            .unwrap(),
        vec![1; 64]
    );
}

#[tokio::test]
async fn grant_creation_waits_for_rotation_and_stale_consent_is_rejected() {
    for thumbprint in [false, true] {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        let existing = storage
            .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
            .await
            .unwrap();
        let client_id = client(&storage).await;
        let mut connection = sqlx::PgConnection::connect_with(&storage.pool.connect_options())
            .await
            .unwrap();
        let mut blocker = connection.begin().await.unwrap();
        sqlx::query("SELECT id FROM oauth_grants WHERE id = $1 FOR UPDATE")
            .bind(existing.id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let rotating = storage.clone();
        let rotation = tokio::spawn(async move {
            rotating
                .rotate_root_key(
                    account.id,
                    0,
                    &[2; 41],
                    &[GrantKeyUpdate {
                        grant_id: existing.id,
                        wrapped_scoped_key: vec![2; 41],
                    }],
                    &[],
                )
                .await
        });
        wait_for_blocked(&mut blocker, 1).await;
        let creating = storage.clone();
        let creation = tokio::spawn(async move {
            if thumbprint {
                creating
                    .get_or_create_oauth_grant_with_thumbprint(
                        client_id,
                        account.id,
                        "sync",
                        "thumbprint",
                    )
                    .await
            } else {
                creating
                    .get_or_create_oauth_grant(client_id, account.id, "sync")
                    .await
            }
        });
        wait_for_blocked(&mut blocker, 2).await;
        blocker.commit().await.unwrap();
        assert_eq!(rotation.await.unwrap().unwrap(), 1);
        let new_grant = creation.await.unwrap().unwrap();
        assert!(new_grant.wrapped_scoped_key.is_none());
        assert!(matches!(
            storage
                .install_consent_key_bundle(
                    new_grant.id,
                    &[1; 41],
                    &serde_json::json!({}),
                    "old",
                    0
                )
                .await
                .unwrap(),
            crate::ConsentKeyInstall::StaleRoot
        ));
        assert!(matches!(
            storage
                .install_consent_key_bundle(
                    new_grant.id,
                    &[2; 41],
                    &serde_json::json!({}),
                    "new",
                    1
                )
                .await
                .unwrap(),
            crate::ConsentKeyInstall::Installed
        ));
    }
}

#[tokio::test]
async fn rotation_fences_concurrent_consent_and_batch_updates() {
    for consent in [false, true] {
        let Some(storage) = test_storage().await else {
            return;
        };
        let account = create_account(&storage).await;
        let grant = storage
            .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
            .await
            .unwrap();
        let mut connection = sqlx::PgConnection::connect_with(&storage.pool.connect_options())
            .await
            .unwrap();
        let mut blocker = connection.begin().await.unwrap();
        sqlx::query("SELECT id FROM oauth_grants WHERE id = $1 FOR UPDATE")
            .bind(grant.id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let rotating = storage.clone();
        let rotation = tokio::spawn(async move {
            rotating
                .rotate_root_key(
                    account.id,
                    0,
                    &[2; 41],
                    &[GrantKeyUpdate {
                        grant_id: grant.id,
                        wrapped_scoped_key: vec![2; 41],
                    }],
                    &[],
                )
                .await
        });
        wait_for_blocked(&mut blocker, 1).await;
        let updating = storage.clone();
        let update = tokio::spawn(async move {
            if consent {
                assert!(matches!(
                    updating
                        .install_consent_key_bundle(
                            grant.id,
                            &[1; 41],
                            &serde_json::json!({}),
                            "old",
                            0
                        )
                        .await
                        .unwrap(),
                    crate::ConsentKeyInstall::StaleRoot
                ));
            } else {
                assert!(matches!(
                    updating
                        .batch_update_grant_wrapped_keys(
                            account.id,
                            0,
                            &[GrantKeyUpdate {
                                grant_id: grant.id,
                                wrapped_scoped_key: vec![1; 41]
                            }]
                        )
                        .await,
                    Err(StorageError::RootKeyVersionConflict)
                ));
            }
        });
        wait_for_blocked(&mut blocker, 2).await;
        blocker.commit().await.unwrap();
        assert_eq!(rotation.await.unwrap().unwrap(), 1);
        update.await.unwrap();
        let stored = storage.get_oauth_grant(grant.id).await.unwrap();
        assert_eq!(stored.wrapped_scoped_key, Some(vec![2; 41]));
        assert!(stored.app_keypair_blob.is_none());
    }
}

#[tokio::test]
async fn batch_updates_enforce_ownership_and_roll_back_earlier_writes() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let other = storage
        .get_or_create_account(TEST_ISSUER, "other", "other@example.com")
        .await
        .unwrap();
    let client_id = client(&storage).await;
    let owned = storage
        .get_or_create_oauth_grant(client_id, account.id, "sync")
        .await
        .unwrap();
    let foreign = storage
        .get_or_create_oauth_grant(client_id, other.id, "sync")
        .await
        .unwrap();
    for rejected in [foreign.id, Uuid::new_v4()] {
        assert!(matches!(
            storage
                .batch_update_grant_wrapped_keys(
                    account.id,
                    0,
                    &[
                        GrantKeyUpdate {
                            grant_id: owned.id,
                            wrapped_scoped_key: vec![1; 41]
                        },
                        GrantKeyUpdate {
                            grant_id: rejected,
                            wrapped_scoped_key: vec![2; 41]
                        },
                    ]
                )
                .await,
            Err(StorageError::OAuthGrantNotFound)
        ));
        assert!(storage
            .get_oauth_grant(owned.id)
            .await
            .unwrap()
            .wrapped_scoped_key
            .is_none());
        assert!(storage
            .get_oauth_grant(foreign.id)
            .await
            .unwrap()
            .wrapped_scoped_key
            .is_none());
    }
    storage
        .batch_update_grant_wrapped_keys(
            account.id,
            0,
            &[GrantKeyUpdate {
                grant_id: owned.id,
                wrapped_scoped_key: vec![3; 41],
            }],
        )
        .await
        .unwrap();
    assert_eq!(
        storage
            .get_oauth_grant(owned.id)
            .await
            .unwrap()
            .wrapped_scoped_key,
        Some(vec![3; 41])
    );
}

#[tokio::test]
async fn root_versions_cannot_wrap_to_a_valid_database_version() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    for version in [1_i64 << 32, -(1_i64 << 32), i64::MAX, -1] {
        assert!(matches!(
            storage
                .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], version)
                .await,
            Err(StorageError::RootKeyVersionConflict)
        ));
        assert!(matches!(
            storage
                .install_consent_key_bundle(
                    grant.id,
                    &[1; 41],
                    &serde_json::json!({}),
                    "blob",
                    version
                )
                .await
                .unwrap(),
            crate::ConsentKeyInstall::StaleRoot
        ));
        assert!(matches!(
            storage
                .rotate_root_key(
                    account.id,
                    version,
                    &[1; 41],
                    &[GrantKeyUpdate {
                        grant_id: grant.id,
                        wrapped_scoped_key: vec![1; 41]
                    }],
                    &[]
                )
                .await,
            Err(StorageError::RootKeyVersionConflict)
        ));
    }
    assert_eq!(
        storage
            .get_account_by_id(account.id)
            .await
            .unwrap()
            .root_key_version,
        0
    );
    assert!(storage
        .get_oauth_grant(grant.id)
        .await
        .unwrap()
        .wrapped_scoped_key
        .is_none());
}

#[tokio::test]
async fn stale_wrapper_only_consent_cannot_replace_an_installed_bundle() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    assert!(grant.wrapped_scoped_key.is_none()); // Request A reads an empty grant.
    let public = serde_json::json!({"kty": "EC", "test": "original"});
    storage
        .install_consent_key_bundle(grant.id, &[2; 41], &public, "bundle-for-key-2", 0)
        .await
        .unwrap();
    // Request A resumes after B has installed its complete bundle, at the same root version.
    assert!(storage
        .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], 0)
        .await
        .is_err());
    let stored = storage.get_oauth_grant(grant.id).await.unwrap();
    assert_eq!(stored.wrapped_scoped_key, Some(vec![2; 41]));
    assert_eq!(stored.app_keypair_blob.as_deref(), Some("bundle-for-key-2"));
    assert_eq!(stored.app_public_key, Some(public));
    storage
        .update_grant_wrapped_scoped_key_root_checked(grant.id, &[2; 41], 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn wrapper_only_consent_initializes_absent_or_empty_keys_and_rejects_replacements() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    for legacy_empty in [false, true] {
        let grant = storage
            .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
            .await
            .unwrap();
        if legacy_empty {
            storage
                .update_grant_wrapped_scoped_key(grant.id, &[])
                .await
                .unwrap();
        }
        storage
            .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], 0)
            .await
            .unwrap();
        storage
            .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], 0)
            .await
            .unwrap();
        assert!(storage
            .update_grant_wrapped_scoped_key_root_checked(grant.id, &[2; 41], 0)
            .await
            .is_err());
        assert_eq!(
            storage
                .get_oauth_grant(grant.id)
                .await
                .unwrap()
                .wrapped_scoped_key,
            Some(vec![1; 41])
        );
    }
}

#[tokio::test]
async fn concurrent_bundle_and_wrapper_only_consent_preserve_the_winning_key() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let grant = storage
        .get_or_create_oauth_grant(client(&storage).await, account.id, "sync")
        .await
        .unwrap();
    let mut connection = sqlx::PgConnection::connect_with(&storage.pool.connect_options())
        .await
        .unwrap();
    let mut blocker = connection.begin().await.unwrap();
    sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account.id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let installing = storage.clone();
    let bundle = tokio::spawn(async move {
        installing
            .install_consent_key_bundle(
                grant.id,
                &[2; 41],
                &serde_json::json!({"kty": "EC"}),
                "bundle-for-key-2",
                0,
            )
            .await
    });
    wait_for_blocked(&mut blocker, 1).await;
    let updating = storage.clone();
    let wrapper = tokio::spawn(async move {
        updating
            .update_grant_wrapped_scoped_key_root_checked(grant.id, &[1; 41], 0)
            .await
    });
    wait_for_blocked(&mut blocker, 2).await;
    blocker.commit().await.unwrap();
    assert!(matches!(
        bundle.await.unwrap().unwrap(),
        crate::ConsentKeyInstall::Installed
    ));
    assert!(matches!(
        wrapper.await.unwrap(),
        Err(StorageError::GrantKeyConflict)
    ));
    let stored = storage.get_oauth_grant(grant.id).await.unwrap();
    assert_eq!(stored.wrapped_scoped_key, Some(vec![2; 41]));
    assert_eq!(stored.app_keypair_blob.as_deref(), Some("bundle-for-key-2"));
    assert_eq!(
        stored.app_public_key,
        Some(serde_json::json!({"kty": "EC"}))
    );
}
