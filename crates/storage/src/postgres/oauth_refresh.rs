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

async fn lock_refresh_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant_id: Uuid,
) -> Result<(), StorageError> {
    // Match credential revocation's account-first lock order. Otherwise a
    // refresh inserted during revocation can escape the DELETE's snapshot.
    sqlx::query_scalar!(
        r#"
        SELECT a.id FROM accounts a
        JOIN oauth_grants g ON g.account_id = a.id
        WHERE g.id = $1
        FOR UPDATE OF a
        "#,
        grant_id,
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(StorageError::from)?
    .ok_or(StorageError::AccountNotFound)?;
    Ok(())
}

#[async_trait]
impl OAuthRefreshTokenStorage for PostgresStorage {
    async fn create_refresh_token(&self, token: &OAuthRefreshToken) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        lock_refresh_account(&mut tx, token.grant_id).await?;
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
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
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
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        lock_refresh_account(&mut tx, grant_id).await?;
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id = $1",
            grant_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
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
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        sqlx::query_scalar!(
            "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id IN (SELECT id FROM oauth_grants WHERE account_id = $1)",
            account_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
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
        lock_refresh_account(&mut tx, grant_id).await?;

        // Delete the old token
        let deleted = sqlx::query!(
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

        // The handler may have read this token before a credential change
        // revoked it. A missing token with no reuse record cannot rotate.
        // Dropping the transaction also discards the hash inserted above.
        if deleted.rows_affected() == 0 {
            return Err(StorageError::RefreshTokenNotFound);
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
#[path = "oauth_refresh_tests.rs"]
mod tests;
