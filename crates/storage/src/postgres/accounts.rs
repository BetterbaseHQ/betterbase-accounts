use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Account, AccountStorage, RootKeyStorage, StorageError};

use super::PostgresStorage;

struct AccountRow {
    id: Uuid,
    issuer: String,
    username: String,
    email: String,
    opaque_registration: Option<Vec<u8>>,
    wrapped_root_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AccountRow> for Account {
    fn from(r: AccountRow) -> Self {
        Account {
            id: r.id,
            issuer: r.issuer,
            username: r.username,
            email: r.email,
            opaque_registration: r.opaque_registration,
            wrapped_root_key: r.wrapped_root_key,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[async_trait]
impl AccountStorage for PostgresStorage {
    async fn get_or_create_account(
        &self,
        issuer: &str,
        username: &str,
        email: &str,
    ) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            INSERT INTO accounts (issuer, username, email)
            VALUES ($1, $2, $3)
            ON CONFLICT (issuer, username) DO UPDATE SET issuer = EXCLUDED.issuer
            RETURNING id, issuer, username, email,
                      opaque_registration, wrapped_root_key,
                      created_at, updated_at
            "#,
            issuer,
            username,
            email,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(row.into())
    }

    async fn get_account_by_id(&self, id: Uuid) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_registration, wrapped_root_key,
                   created_at, updated_at
            FROM accounts WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn get_account_by_username(
        &self,
        issuer: &str,
        username: &str,
    ) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_registration, wrapped_root_key,
                   created_at, updated_at
            FROM accounts WHERE issuer = $1 AND username = $2
            "#,
            issuer,
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn get_account_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_registration, wrapped_root_key,
                   created_at, updated_at
            FROM accounts WHERE issuer = $1 AND email = $2
            "#,
            issuer,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn finalize_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_registration = $2
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }

    async fn finalize_registration_with_root_key(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_registration = $2, wrapped_root_key = $3
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
            wrapped_root_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }

    async fn update_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_registration = $2
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }

    async fn delete_account(&self, account_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM accounts WHERE id = $1", account_id)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }
}

#[async_trait]
impl RootKeyStorage for PostgresStorage {
    async fn get_wrapped_root_key(&self, account_id: Uuid) -> Result<Vec<u8>, StorageError> {
        let row = sqlx::query!(
            "SELECT wrapped_root_key FROM accounts WHERE id = $1",
            account_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        row.wrapped_root_key
            .ok_or(StorageError::WrappedRootKeyNotFound)
    }

    async fn set_wrapped_root_key(
        &self,
        account_id: Uuid,
        wrapped_key: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            "UPDATE accounts SET wrapped_root_key = $2 WHERE id = $1",
            account_id,
            wrapped_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }
}
