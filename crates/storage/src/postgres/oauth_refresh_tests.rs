use super::*;
use crate::{AccountStorage, CompositeStorage, OAuthClientStorage, OAuthGrantStorage};

use super::super::test_support::{create_account, test_storage};

fn record(grant_id: Uuid, seed: u8) -> OAuthRefreshToken {
    let now = Utc::now();
    OAuthRefreshToken {
        id: Uuid::new_v4(),
        grant_id,
        token_hash: vec![seed; 32],
        created_at: now,
        expires_at: now + chrono::Duration::days(1),
    }
}

async fn seed_grant(storage: &PostgresStorage) -> crate::OAuthGrant {
    let account = create_account(storage).await;
    let client_id = Uuid::new_v4();
    storage
        .create_oauth_client(&crate::OAuthClient {
            id: client_id,
            name: "test client".to_owned(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:5381/".to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            created_at: Utc::now(),
        })
        .await
        .expect("create client");
    storage
        .get_or_create_oauth_grant(client_id, account.id, "openid")
        .await
        .expect("create grant")
}

#[tokio::test]
async fn sequential_reuse_reports_reused_and_revokes_surviving_family() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;

    let t1 = record(grant.id, 1);
    storage.create_refresh_token(&t1).await.expect("create t1");

    // Normal rotation: t1 -> t2.
    let t2 = record(grant.id, 2);
    storage
        .rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t2)
        .await
        .expect("rotate");

    // Presenting t1 again is sequential reuse: it must be reported as
    // RefreshTokenReused and revoke the surviving family (t2), not
    // leave the replacement active.
    let t3 = record(grant.id, 3);
    let err = storage
        .rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t3)
        .await
        .expect_err("reuse must fail");
    assert!(
        matches!(err, StorageError::RefreshTokenReused { .. }),
        "expected RefreshTokenReused, got: {err:?}"
    );
    assert!(matches!(
        storage.get_refresh_token_by_hash(&t2.token_hash).await,
        Err(StorageError::RefreshTokenNotFound)
    ));
}

#[tokio::test]
async fn concurrent_presenters_of_one_token_one_family_revoked() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;

    let t1 = record(grant.id, 1);
    storage.create_refresh_token(&t1).await.expect("create t1");

    // Two rotations of the SAME token in flight at once (post-fix the
    // duplicate used-hash is detected via ON CONFLICT rows_affected,
    // not an aborting INSERT): exactly one may win; the loser's
    // conflict must revoke the family including the winner's token.
    let t2 = record(grant.id, 2);
    let t3 = record(grant.id, 3);
    let (r1, r2) = tokio::join!(
        storage.rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t2),
        storage.rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t3),
    );
    let ok_count = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
    assert_eq!(ok_count, 1, "results: {r1:?} {r2:?}");
    // Whichever token the winner created is gone — the family was
    // revoked by the loser's conflict detection.
    for t in [&t2, &t3] {
        let found = storage
            .get_refresh_token_by_hash(&t.token_hash)
            .await
            .is_ok();
        assert!(!found, "family must be fully revoked");
    }
}

#[tokio::test]
async fn refresh_read_before_credential_change_cannot_resurrect_session() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;
    let original = record(grant.id, 1);
    storage.create_refresh_token(&original).await.unwrap();
    // The request has already passed its initial lookup when the
    // password change commits, but has not yet consumed the token.
    let previously_read = storage
        .get_refresh_token_by_hash(&original.token_hash)
        .await
        .unwrap();
    storage
        .update_credentials_and_revoke_sessions(
            grant.account_id,
            b"replacement credentials",
            None,
            0,
            0,
            None,
        )
        .await
        .unwrap();
    let replacement = record(grant.id, 2);
    assert!(matches!(
        storage
            .rotate_refresh_token(
                previously_read.id,
                &previously_read.token_hash,
                grant.id,
                &replacement,
            )
            .await,
        Err(StorageError::RefreshTokenNotFound)
    ));
    assert!(matches!(
        storage
            .get_refresh_token_by_hash(&replacement.token_hash)
            .await,
        Err(StorageError::RefreshTokenNotFound)
    ));
    assert_eq!(
        storage
            .get_used_refresh_grant_by_hash(&original.token_hash)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn concurrent_refresh_and_credential_change_leave_no_refresh_token() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;
    let original = record(grant.id, 1);
    storage.create_refresh_token(&original).await.unwrap();
    let replacement = record(grant.id, 2);
    let (rotation, revocation) = tokio::join!(
        storage.rotate_refresh_token(original.id, &original.token_hash, grant.id, &replacement,),
        storage.revoke_account_sessions(grant.account_id),
    );
    assert_eq!(revocation.unwrap(), 1);
    assert!(matches!(
        rotation,
        Ok(()) | Err(StorageError::RefreshTokenNotFound)
    ));
    for token in [original, replacement] {
        assert!(matches!(
            storage.get_refresh_token_by_hash(&token.token_hash).await,
            Err(StorageError::RefreshTokenNotFound)
        ));
    }
}

#[tokio::test]
async fn concurrent_refresh_and_family_revocation_leave_no_refresh_token() {
    let Some(storage) = test_storage().await else {
        return;
    };
    for by_account in [false, true] {
        let grant = seed_grant(&storage).await;
        let original = record(grant.id, if by_account { 3 } else { 1 });
        let replacement = record(grant.id, if by_account { 4 } else { 2 });
        storage.create_refresh_token(&original).await.unwrap();
        let revoke = async {
            if by_account {
                storage
                    .delete_refresh_tokens_by_account(grant.account_id)
                    .await
            } else {
                storage.delete_refresh_tokens_by_grant(grant.id).await
            }
        };
        let (rotation, revocation) = tokio::join!(
            storage
                .rotate_refresh_token(original.id, &original.token_hash, grant.id, &replacement,),
            revoke,
        );
        revocation.unwrap();
        assert!(matches!(
            rotation,
            Ok(()) | Err(StorageError::RefreshTokenNotFound)
        ));
        for token in [original, replacement] {
            assert!(matches!(
                storage.get_refresh_token_by_hash(&token.token_hash).await,
                Err(StorageError::RefreshTokenNotFound)
            ));
        }
    }
}

#[tokio::test]
async fn refresh_writes_and_revocations_wait_for_account_lock() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;
    let original = record(grant.id, 1);
    let replacement = record(grant.id, 2);
    for operation in 0..4 {
        let mut tx = storage.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(grant.account_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let write = async {
            match operation {
                0 => storage.create_refresh_token(&original).await,
                1 => {
                    storage
                        .rotate_refresh_token(
                            original.id,
                            &original.token_hash,
                            grant.id,
                            &replacement,
                        )
                        .await
                }
                2 => storage.delete_refresh_tokens_by_grant(grant.id).await,
                _ => {
                    storage
                        .delete_refresh_tokens_by_account(grant.account_id)
                        .await
                }
            }
        };
        tokio::pin!(write);
        // A credential change holds this same lock until its refresh
        // deletion commits, so no writer or revoker may bypass it.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut write)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        write.await.unwrap();
    }
}

#[tokio::test]
async fn used_token_lookup_resolves_the_grant() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let grant = seed_grant(&storage).await;

    let t1 = record(grant.id, 7);
    storage.create_refresh_token(&t1).await.expect("create t1");
    assert_eq!(
        storage
            .get_used_refresh_grant_by_hash(&t1.token_hash)
            .await
            .expect("lookup unused"),
        None
    );

    let t2 = record(grant.id, 8);
    storage
        .rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t2)
        .await
        .expect("rotate");
    assert_eq!(
        storage
            .get_used_refresh_grant_by_hash(&t1.token_hash)
            .await
            .expect("lookup used"),
        Some(grant.id)
    );
}
