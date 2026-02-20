use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{StorageError, UserKey, UserKeyStorage};

use super::PostgresStorage;

/// Maximum number of keys per (account, service) pair.
const MAX_KEYS_PER_SERVICE: i64 = 10;

struct UserKeyRow {
    account_id: Uuid,
    service: String,
    key_name: String,
    key_material: Vec<u8>,
    serial_number: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserKeyRow> for UserKey {
    fn from(r: UserKeyRow) -> Self {
        UserKey {
            account_id: r.account_id,
            service: r.service,
            key_name: r.key_name,
            key_material: r.key_material,
            serial_number: r.serial_number,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[async_trait]
impl UserKeyStorage for PostgresStorage {
    async fn list_user_keys(&self, account_id: Uuid) -> Result<Vec<UserKey>, StorageError> {
        let rows = sqlx::query_as!(
            UserKeyRow,
            r#"
            SELECT account_id, service, key_name, key_material,
                   serial_number, created_at, updated_at
            FROM user_keys
            WHERE account_id = $1
            ORDER BY service, key_name
            "#,
            account_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_user_key(
        &self,
        account_id: Uuid,
        service: &str,
        key_name: &str,
    ) -> Result<UserKey, StorageError> {
        let row = sqlx::query_as!(
            UserKeyRow,
            r#"
            SELECT account_id, service, key_name, key_material,
                   serial_number, created_at, updated_at
            FROM user_keys
            WHERE account_id = $1 AND service = $2 AND key_name = $3
            "#,
            account_id,
            service,
            key_name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::KeyNotFound)?;

        Ok(row.into())
    }

    async fn store_user_key(
        &self,
        account_id: Uuid,
        service: &str,
        key_name: &str,
        key_material: &[u8],
    ) -> Result<(), StorageError> {
        // Check key count for this service (only count distinct names; upsert won't increase count)
        let existing = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM user_keys WHERE account_id = $1 AND service = $2",
            account_id,
            service,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?
        .unwrap_or(0);

        // Check if this key_name already exists for this account+service
        let name_exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM user_keys WHERE account_id = $1 AND service = $2 AND key_name = $3)",
            account_id,
            service,
            key_name,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?
        .unwrap_or(false);

        if !name_exists && existing >= MAX_KEYS_PER_SERVICE {
            return Err(StorageError::MaxKeysExceeded);
        }

        sqlx::query!(
            r#"
            INSERT INTO user_keys (account_id, service, key_name, key_material, serial_number)
            VALUES ($1, $2, $3, $4, 1)
            ON CONFLICT (account_id, service, key_name) DO UPDATE
            SET key_material  = EXCLUDED.key_material,
                serial_number = user_keys.serial_number + 1
            "#,
            account_id,
            service,
            key_name,
            key_material,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(())
    }
}
