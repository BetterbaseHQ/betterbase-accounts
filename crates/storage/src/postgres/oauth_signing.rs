use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{OAuthSigningKey, OAuthSigningKeyStorage, StorageError};

use super::PostgresStorage;

struct OAuthSigningKeyRow {
    id: i32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl From<OAuthSigningKeyRow> for OAuthSigningKey {
    fn from(r: OAuthSigningKeyRow) -> Self {
        OAuthSigningKey {
            id: r.id,
            private_key: r.private_key,
            public_key: r.public_key,
            created_at: r.created_at,
        }
    }
}

#[async_trait]
impl OAuthSigningKeyStorage for PostgresStorage {
    async fn ensure_oauth_signing_key(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_signing_keys (private_key, public_key)
            SELECT $1, $2
            WHERE NOT EXISTS (SELECT 1 FROM oauth_signing_keys)
            "#,
            private_key,
            public_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_current_signing_key(&self) -> Result<OAuthSigningKey, StorageError> {
        let row = sqlx::query_as!(
            OAuthSigningKeyRow,
            "SELECT id, private_key, public_key, created_at FROM oauth_signing_keys ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::KeyNotFound)?;

        Ok(row.into())
    }

    async fn get_signing_key_by_id(&self, kid: i32) -> Result<OAuthSigningKey, StorageError> {
        let row = sqlx::query_as!(
            OAuthSigningKeyRow,
            "SELECT id, private_key, public_key, created_at FROM oauth_signing_keys WHERE id = $1",
            kid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::KeyNotFound)?;

        Ok(row.into())
    }

    async fn list_signing_keys(&self) -> Result<Vec<OAuthSigningKey>, StorageError> {
        let rows = sqlx::query_as!(
            OAuthSigningKeyRow,
            "SELECT id, private_key, public_key, created_at FROM oauth_signing_keys ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}
