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

// Every root-dependent write locks the account before any grant rows, matching
// rotation's lock order. Keep the version check and write in one transaction.
async fn lock_grant_root(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant_id: Uuid,
) -> Result<i64, StorageError> {
    sqlx::query_scalar!(
        "SELECT root_key_version FROM accounts WHERE id = (SELECT account_id FROM oauth_grants WHERE id = $1) FOR UPDATE",
        grant_id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(StorageError::from)?
    .map(i64::from)
    .ok_or(StorageError::OAuthGrantNotFound)
}

#[async_trait]
impl OAuthGrantStorage for PostgresStorage {
    async fn get_or_create_oauth_grant(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
    ) -> Result<OAuthGrant, StorageError> {
        // AUD-009 review: serialize grant creation against root rotation
        // (which locks the account row before checking grant-set
        // completeness) so a new grant cannot commit mid-rotation and end
        // up wrapped under the retired root.
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let locked = sqlx::query_scalar!(
            "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        if locked.is_none() {
            return Err(StorageError::AccountNotFound);
        }
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            INSERT INTO oauth_grants (client_id, account_id, scope)
            VALUES ($1, $2, $3)
            ON CONFLICT (client_id, account_id) DO UPDATE
            -- AUD-013: the stored grant tracks the CURRENT authorization's
            -- scope, so refresh cannot resurrect a historically broader
            -- consent after a later narrow one
            SET scope        = EXCLUDED.scope,
                last_used_at = NOW()
            RETURNING id, client_id, account_id, scope,
                      keys_jwk_thumbprint, app_public_key, app_keypair_blob,
                      wrapped_scoped_key, mailbox_id,
                      created_at, updated_at, last_used_at
            "#,
            client_id,
            account_id,
            scope,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;

        Ok(row.into())
    }

    async fn get_or_create_oauth_grant_with_thumbprint(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
        thumbprint: &str,
    ) -> Result<OAuthGrant, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let locked = sqlx::query_scalar!(
            "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        if locked.is_none() {
            return Err(StorageError::AccountNotFound);
        }
        let row = sqlx::query_as!(
            OAuthGrantRow,
            r#"
            INSERT INTO oauth_grants (client_id, account_id, scope, keys_jwk_thumbprint)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (client_id, account_id) DO UPDATE
            SET keys_jwk_thumbprint = EXCLUDED.keys_jwk_thumbprint,
                scope               = EXCLUDED.scope,
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
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
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
            root_key_version: i32,
            credentials_version: i32,
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
                a.root_key_version,
                a.credentials_version,
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
            root_key_version: i64::from(row.root_key_version),
            credentials_version: i64::from(row.credentials_version),
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

    async fn install_consent_key_bundle(
        &self,
        grant_id: Uuid,
        wrapped_scoped_key: &[u8],
        public_key: &serde_json::Value,
        blob: &str,
        expected_root_version: i64,
    ) -> Result<crate::ConsentKeyInstall, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let current_root_version = lock_grant_root(&mut tx, grant_id).await?;
        if current_root_version != expected_root_version {
            return Ok(crate::ConsentKeyInstall::StaleRoot);
        }
        let stored = sqlx::query_scalar!(
            "SELECT wrapped_scoped_key FROM oauth_grants WHERE id = $1 FOR UPDATE",
            grant_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthGrantNotFound)?;

        let outcome = match stored.as_deref() {
            // An empty stored wrapper is an absent one (legacy rows /
            // server pre-history) — treating it as occupied would 409-loop
            // against a client that correctly reads it as absent.
            None | Some(&[]) => {
                sqlx::query!(
                    r#"
                    UPDATE oauth_grants
                    SET wrapped_scoped_key = $2, app_public_key = $3, app_keypair_blob = $4,
                        updated_at = NOW()
                    WHERE id = $1
                    "#,
                    grant_id,
                    wrapped_scoped_key,
                    public_key,
                    blob,
                )
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;
                crate::ConsentKeyInstall::Installed
            }
            Some(stored_bytes) if stored_bytes == wrapped_scoped_key => {
                sqlx::query!(
                    r#"
                    UPDATE oauth_grants
                    SET app_public_key = $2, app_keypair_blob = $3, updated_at = NOW()
                    WHERE id = $1
                    "#,
                    grant_id,
                    public_key,
                    blob,
                )
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;
                crate::ConsentKeyInstall::Installed
            }
            Some(_) => crate::ConsentKeyInstall::Conflict,
        };
        tx.commit().await.map_err(StorageError::from)?;
        Ok(outcome)
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

    async fn update_grant_wrapped_scoped_key_root_checked(
        &self,
        grant_id: Uuid,
        wrapped_scoped_key: &[u8],
        expected_root_version: i64,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let current = lock_grant_root(&mut tx, grant_id).await?;
        if current != expected_root_version {
            tx.rollback().await.map_err(StorageError::from)?;
            return Err(StorageError::RootKeyVersionConflict);
        }
        // The caller's empty-grant snapshot may predate another consent. Check
        // the stored wrapper under the same locks as the write to preserve any
        // installed bundle and the key used to encrypt it.
        let stored = sqlx::query_scalar!(
            "SELECT wrapped_scoped_key FROM oauth_grants WHERE id = $1 FOR UPDATE",
            grant_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthGrantNotFound)?;
        if let Some(stored) = stored.filter(|key| !key.is_empty()) {
            if stored != wrapped_scoped_key {
                return Err(StorageError::GrantKeyConflict);
            }
            tx.commit().await.map_err(StorageError::from)?;
            return Ok(());
        }
        sqlx::query!(
            "UPDATE oauth_grants SET wrapped_scoped_key = $2 WHERE id = $1",
            grant_id,
            wrapped_scoped_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
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
        account_id: Uuid,
        client_id: Uuid,
        mailbox_id: &str,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        // Lock and check ownership together, so deletion cannot race a checked write.
        sqlx::query_scalar!(
            "SELECT id FROM oauth_grants WHERE id = $1 AND account_id = $2 AND client_id = $3 FOR UPDATE",
            grant_id, account_id, client_id
        ).fetch_optional(&mut *tx).await.map_err(StorageError::from)?
            .ok_or(StorageError::OAuthGrantNotFound)?;
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
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            // The same mailbox cannot belong to two grants.
            if let sqlx::Error::Database(ref db) = e {
                if db.constraint() == Some("idx_oauth_grants_mailbox_id") {
                    return StorageError::MailboxConflict;
                }
            }
            StorageError::from(e)
        })?;
        tx.commit().await.map_err(StorageError::from)?;
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
        account_id: Uuid,
        expected_root_version: i64,
        updates: &[GrantKeyUpdate],
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let version = sqlx::query_scalar!(
            "SELECT root_key_version FROM accounts WHERE id = $1 FOR UPDATE",
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;
        if i64::from(version) != expected_root_version {
            return Err(StorageError::RootKeyVersionConflict);
        }
        for update in updates {
            let owner = sqlx::query_scalar!(
                "SELECT account_id FROM oauth_grants WHERE id = $1",
                update.grant_id
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(StorageError::from)?;
            if owner != Some(account_id) {
                return Err(StorageError::OAuthGrantNotFound);
            }
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
