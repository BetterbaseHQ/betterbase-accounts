//! PostgreSQL storage implementation using sqlx.

mod accounts;
mod cleanup;
mod composite;
mod jwt_keys;
mod login;
mod oauth_clients;
mod oauth_codes;
mod oauth_grants;
mod oauth_refresh;
mod oauth_signing;
mod rate_limit;
mod recovery;
mod registration;
mod user_keys;
mod verification;

use sqlx::PgPool;

/// PostgreSQL-backed storage implementation.
///
/// Cheaply cloneable — all clones share the same connection pool.
#[derive(Clone, Debug)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Create a new storage instance from an existing pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect and run pending migrations.
    pub async fn connect_and_migrate(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self::new(pool))
    }

    /// Run pending migrations on an existing pool.
    pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::migrate!().run(pool).await?;
        Ok(())
    }

    /// Access the underlying pool (for tests / admin tools).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
