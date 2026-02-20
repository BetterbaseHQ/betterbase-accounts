use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Account, GrantKeyUpdate, OAuthGrant, OAuthGrantStorage, StorageError};

use super::PostgresStorage;

struct OAuthGrantRow {
    id: Uuid,
    client_id: Uuid,
    account_id: Uuid,
    scope: String,
    keys_jwk_thumbprint: Option<String>,
    app_public_key: Option<serde_json::Value>,
    app_keypair_blob: Option<String>,
    wrapped_scoped_key: Option<Vec<u8>>,
    mailbox_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
}

impl From<OAuthGrantRow> for OAuthGrant {
    fn from(r: OAuthGrantRow) -> Self {
        OAuthGrant {
            id: r.id,
            client_id: r.client_id,
            account_id: r.account_id,
            scope: r.scope,
            keys_jwk_thumbprint: r.keys_jwk_thumbprint,
            app_public_key: r.app_public_key,
            app_keypair_blob: r.app_keypair_blob,
            wrapped_scoped_key: r.wrapped_scoped_key,
            mailbox_id: r.mailbox_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_used_at: r.last_used_at,
        }
    }
}

#[async_trait]
impl OAuthGrantStorage for PostgresStorage {
    async fn get_or_create_oauth_grant(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
    ) -> Result<OAuthGrant, StorageError> {
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            INSERT INTO oauth_grants (client_id, account_id, scope)
            VALUES ($1, $2, $3)
            ON CONFLICT (client_id, account_id) DO UPDATE SET last_used_at = NOW()
            RETURNING id, client_id, account_id, scope,
                      keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                      wrapped_scoped_key, mailbox_id,
                      created_at, updated_at, last_used_at
            "#,
            client_id,
            account_id,
            scope,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(row.into())
    }

    async fn get_or_create_oauth_grant_with_thumbprint(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
        thumbprint: &str,
    ) -> Result<OAuthGrant, StorageError> {
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            INSERT INTO oauth_grants (client_id, account_id, scope, keys_jwk_thumbprint)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (client_id, account_id) DO UPDATE
            SET keys_jwk_thumbprint = EXCLUDED.keys_jwk_thumbprint,
                last_used_at        = NOW()
            RETURNING id, client_id, account_id, scope,
                      keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                      wrapped_scoped_key, mailbox_id,
                      created_at, updated_at, last_used_at
            "#,
            client_id,
            account_id,
            scope,
            thumbprint,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(row.into())
    }

    async fn get_oauth_grant(&self, grant_id: Uuid) -> Result<OAuthGrant, StorageError> {
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            SELECT id, client_id, account_id, scope,
                   keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                   wrapped_scoped_key, mailbox_id,
                   created_at, updated_at, last_used_at
            FROM oauth_grants WHERE id = $1
            "#,
            grant_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthGrantNotFound)?;

        Ok(row.into())
    }

    async fn get_oauth_grant_by_account_and_client(
        &self,
        account_id: Uuid,
        client_id: Uuid,
    ) -> Result<OAuthGrant, StorageError> {
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            SELECT id, client_id, account_id, scope,
                   keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                   wrapped_scoped_key, mailbox_id,
                   created_at, updated_at, last_used_at
            FROM oauth_grants WHERE account_id = $1 AND client_id = $2
            "#,
            account_id,
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthGrantNotFound)?;

        Ok(row.into())
    }

    async fn get_account_by_key_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Result<(Account, OAuthGrant), StorageError> {
        struct Row {
            // Grant fields
            grant_id: Uuid,
            client_id: Uuid,
            account_id: Uuid,
            scope: String,
            keys_jwk_thumbprint: Option<String>,
            app_public_key: Option<serde_json::Value>,
            app_keypair_blob: Option<String>,
            wrapped_scoped_key: Option<Vec<u8>>,
            mailbox_id: Option<String>,
            grant_created_at: DateTime<Utc>,
            grant_updated_at: DateTime<Utc>,
            last_used_at: DateTime<Utc>,
            // Account fields
            acc_id: Uuid,
            issuer: String,
            username: String,
            email: String,
            opaque_record: Option<Vec<u8>>,
            wrapped_root_key: Option<Vec<u8>>,
            acc_created_at: DateTime<Utc>,
            acc_updated_at: DateTime<Utc>,
        }

        let row = sqlx::query_as!(
            Row,
            r#"
            SELECT
                g.id            AS grant_id,
                g.client_id,
                g.account_id,
                g.scope,
                g.keys_jwk_thumbprint,
                g.app_public_key,
                g.app_keypair_blob,
                g.wrapped_scoped_key,
                g.mailbox_id,
                g.created_at    AS grant_created_at,
                g.updated_at    AS grant_updated_at,
                g.last_used_at,
                a.id            AS acc_id,
                a.issuer,
                a.username,
                a.email,
                a.opaque_record,
                a.wrapped_root_key,
                a.created_at    AS acc_created_at,
                a.updated_at    AS acc_updated_at
            FROM oauth_grants g
            JOIN accounts a ON a.id = g.account_id
            WHERE g.keys_jwk_thumbprint = $1
            "#,
            thumbprint,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        let account = Account {
            id: row.acc_id,
            issuer: row.issuer,
            username: row.username,
            email: row.email,
            opaque_record: row.opaque_record,
            wrapped_root_key: row.wrapped_root_key,
            created_at: row.acc_created_at,
            updated_at: row.acc_updated_at,
        };
        let grant = OAuthGrant {
            id: row.grant_id,
            client_id: row.client_id,
            account_id: row.account_id,
            scope: row.scope,
            keys_jwk_thumbprint: row.keys_jwk_thumbprint,
            app_public_key: row.app_public_key,
            app_keypair_blob: row.app_keypair_blob,
            wrapped_scoped_key: row.wrapped_scoped_key,
            mailbox_id: row.mailbox_id,
            created_at: row.grant_created_at,
            updated_at: row.grant_updated_at,
            last_used_at: row.last_used_at,
        };
        Ok((account, grant))
    }

    async fn update_grant_last_used(&self, grant_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE oauth_grants SET last_used_at = NOW() WHERE id = $1",
            grant_id,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn update_grant_keypair(
        &self,
        grant_id: Uuid,
        public_key: &serde_json::Value,
        blob: &str,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            UPDATE oauth_grants
            SET app_public_key = $2, app_keypair_blob = $3
            WHERE id = $1
            "#,
            grant_id,
            public_key,
            blob,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn update_grant_wrapped_scoped_key(
        &self,
        grant_id: Uuid,
        wrapped_scoped_key: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE oauth_grants SET wrapped_scoped_key = $2 WHERE id = $1",
            grant_id,
            wrapped_scoped_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn update_grant_mailbox_id(
        &self,
        grant_id: Uuid,
        mailbox_id: &str,
    ) -> Result<(), StorageError> {
        // First-write-wins: only update if mailbox_id is not yet set
        sqlx::query!(
            r#"
            UPDATE oauth_grants
            SET mailbox_id = $2
            WHERE id = $1 AND mailbox_id IS NULL
            "#,
            grant_id,
            mailbox_id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Unique constraint violation = another request already set it
            if let sqlx::Error::Database(ref db) = e {
                if db.constraint() == Some("idx_oauth_grants_mailbox_id") {
                    return StorageError::Internal("mailbox_id conflict".to_string());
                }
            }
            StorageError::from(e)
        })?;
        Ok(())
    }

    async fn list_grants_for_account(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<OAuthGrant>, StorageError> {
        let rows = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            SELECT id, client_id, account_id, scope,
                   keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                   wrapped_scoped_key, mailbox_id,
                   created_at, updated_at, last_used_at
            FROM oauth_grants WHERE account_id = $1
            ORDER BY created_at
            "#,
            account_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn batch_update_grant_wrapped_keys(
        &self,
        updates: &[GrantKeyUpdate],
    ) -> Result<(), StorageError> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        for update in updates {
            sqlx::query!(
                "UPDATE oauth_grants SET wrapped_scoped_key = $2 WHERE id = $1",
                update.grant_id,
                update.wrapped_scoped_key.as_slice(),
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }
        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }
}
