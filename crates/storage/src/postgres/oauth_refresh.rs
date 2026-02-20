use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{OAuthRefreshToken, OAuthRefreshTokenStorage, StorageError};

use super::PostgresStorage;

/// Check if a sqlx error is a PostgreSQL unique constraint violation (23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        return db_err.code().as_deref() == Some("23505");
    }
    false
}

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

        // Record the old token hash — plain INSERT (no ON CONFLICT) so a
        // duplicate key violation signals reuse within this transaction.
        let insert_result = sqlx::query!(
            r#"
            INSERT INTO used_refresh_tokens (token_hash, grant_id)
            VALUES ($1, $2)
            "#,
            old_token_hash,
            grant_id,
        )
        .execute(&mut *tx)
        .await;

        if let Err(e) = insert_result {
            if is_unique_violation(&e) {
                // Reuse detected — revoke all refresh tokens for this grant
                // within the same transaction, then abort cleanly.
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
            return Err(StorageError::from(e));
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
