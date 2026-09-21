use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{OAuthRefreshToken, OAuthRefreshTokenStorage, StorageError};

use super::PostgresStorage;

struct OAuthRefreshTokenRow {
    id: Uuid,
    grant_id: Uuid,
    token_hash: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<OAuthRefreshTokenRow> for OAuthRefreshToken {
    fn from(r: OAuthRefreshTokenRow) -> Self {
        OAuthRefreshToken {
            id: r.id,
            grant_id: r.grant_id,
            token_hash: r.token_hash,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

#[async_trait]
impl OAuthRefreshTokenStorage for PostgresStorage {
    async fn create_refresh_token(&self, token: &OAuthRefreshToken) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_refresh_tokens (id, grant_id, token_hash, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            token.id,
            token.grant_id,
            token.token_hash.as_slice(),
            token.created_at,
            token.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_refresh_token_by_hash(
        &self,
        hash: &[u8],
    ) -> Result<OAuthRefreshToken, StorageError> {
        let now = Utc::now();
        let row = sqlx::query_as!(
            OAuthRefreshTokenRow,
            r#"
            SELECT id, grant_id, token_hash, created_at, expires_at
            FROM oauth_refresh_tokens WHERE token_hash = $1
            "#,
            hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::RefreshTokenNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::RefreshTokenExpired);
        }
        Ok(row.into())
    }

    async fn delete_refresh_token(&self, token_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM oauth_refresh_tokens WHERE id = $1", token_id,)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn delete_refresh_tokens_by_grant(&self, grant_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id = $1",
            grant_id,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_used_refresh_grant_by_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Uuid>, StorageError> {
        let grant_id = sqlx::query_scalar!(
            "SELECT grant_id FROM used_refresh_tokens WHERE token_hash = $1",
            hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(grant_id)
    }

    async fn delete_refresh_tokens_by_account(&self, account_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id IN (SELECT id FROM oauth_grants WHERE account_id = $1)",
            account_id,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn rotate_refresh_token(
        &self,
        old_token_id: Uuid,
        old_token_hash: &[u8],
        grant_id: Uuid,
        new_token: &OAuthRefreshToken,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        // Delete the old token
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE id = $1",
            old_token_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        // Record the old token hash. ON CONFLICT DO NOTHING keeps the
        // transaction usable when the hash was already recorded (reuse);
        // detecting reuse via rows_affected avoids a 23505 aborting the
        // transaction before the family revocation below can run (AUD-004:
        // the aborted transaction made the revocation DELETE fail with
        // 25P02 and roll back, leaving the surviving family active).
        let recorded = sqlx::query!(
            r#"
            INSERT INTO used_refresh_tokens (token_hash, grant_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
            old_token_hash,
            grant_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        if recorded.rows_affected() == 0 {
            // Reuse detected — revoke all refresh tokens for this grant
            // within the same committed transaction, then report.
            sqlx::query!(
                "DELETE FROM oauth_refresh_tokens WHERE grant_id = $1",
                grant_id,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
            tx.commit().await.map_err(StorageError::from)?;
            return Err(StorageError::RefreshTokenReused { grant_id });
        }

        // Insert new token
        sqlx::query!(
            r#"
            INSERT INTO oauth_refresh_tokens (id, grant_id, token_hash, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            new_token.id,
            new_token.grant_id,
            new_token.token_hash.as_slice(),
            new_token.created_at,
            new_token.expires_at,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OAuthClientStorage, OAuthGrantStorage};

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
    async fn concurrent_reuse_revokes_family_despite_duplicate_insert_abort() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let grant = seed_grant(&storage).await;

        let t1 = record(grant.id, 1);
        storage.create_refresh_token(&t1).await.expect("create t1");

        // First rotation wins.
        let t2 = record(grant.id, 2);
        storage
            .rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t2)
            .await
            .expect("rotate");

        // A concurrent presenter of the same token records the duplicate
        // hash inside its transaction: the 23505 aborts that transaction,
        // and the family-revoking DELETE must still take effect. Pre-fix,
        // the DELETE failed with 25P02 and rolled everything back.
        let t4 = record(grant.id, 4);
        let err = storage
            .rotate_refresh_token(t1.id, &t1.token_hash, grant.id, &t4)
            .await
            .expect_err("concurrent reuse must fail");
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
}
