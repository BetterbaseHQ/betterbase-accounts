use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{JwtKey, JwtKeyStorage, StorageError};

use super::PostgresStorage;

struct JwtKeyRow {
    id: i32,
    secret_key: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl From<JwtKeyRow> for JwtKey {
    fn from(r: JwtKeyRow) -> Self {
        JwtKey {
            id: r.id,
            secret_key: r.secret_key,
            created_at: r.created_at,
        }
    }
}

#[async_trait]
impl JwtKeyStorage for PostgresStorage {
    async fn get_current_jwt_key(&self) -> Result<JwtKey, StorageError> {
        let row = sqlx::query_as!(
            JwtKeyRow,
            "SELECT id, secret_key, created_at FROM jwt_keys ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::KeyNotFound)?;

        Ok(row.into())
    }

    async fn get_jwt_key_by_id(&self, id: i32) -> Result<JwtKey, StorageError> {
        let row = sqlx::query_as!(
            JwtKeyRow,
            "SELECT id, secret_key, created_at FROM jwt_keys WHERE id = $1",
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::KeyNotFound)?;

        Ok(row.into())
    }

    async fn ensure_jwt_key(&self, secret_key: &[u8]) -> Result<(), StorageError> {
        // Only insert if no key exists (no-op if one already exists)
        sqlx::query!(
            r#"
            INSERT INTO jwt_keys (secret_key)
            SELECT $1
            WHERE NOT EXISTS (SELECT 1 FROM jwt_keys)
            "#,
            secret_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }
}
