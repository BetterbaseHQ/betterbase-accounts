use sqlx::postgres::PgPoolOptions;

use super::PostgresStorage;

// Re-export all domain traits so test modules can `use super::super::test_support::*`
// and have every trait method available on PostgresStorage.
#[allow(unused_imports)]
pub(super) use crate::{
    AccountStorage, RecoveryStorage, RegistrationStateStorage, RootKeyStorage, StorageError,
    VerificationStorage, VerificationTokenStorage,
};

/// Build a storage backed by a throwaway schema when `DATABASE_URL` is set.
///
/// Without `DATABASE_URL` tests skip (return `None`), preserving the fast
/// no-database `just test`. The `just test-db` gate and CI also set
/// `BB_TEST_REQUIRE_DB=1`, which makes a missing or unreachable database fail
/// the run instead of silently skipping every storage test.
pub(super) async fn test_storage() -> Option<PostgresStorage> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => {
            if require_db() {
                panic!("BB_TEST_REQUIRE_DB=1 but DATABASE_URL is not set");
            }
            return None;
        }
    };

    // Each test gets its own schema for full isolation when running in parallel.
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
    let mut opts: sqlx::postgres::PgConnectOptions =
        database_url.parse().expect("parse DATABASE_URL");
    opts = opts.options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap_or_else(|error| panic!("connect test database: {error}"));
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&pool)
        .await
        .expect("create test schema");

    sqlx::migrate!().run(&pool).await.expect("apply migrations");
    Some(PostgresStorage::new(pool))
}

/// Whether DB-backed tests must fail instead of skip. Set by `just test-db`
/// and CI; the gate is enabled only when the variable is exactly `1`.
pub(super) fn require_db() -> bool {
    std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref() == Some("1")
}

pub(super) const TEST_ISSUER: &str = "https://accounts.example.com";
pub(super) const TEST_USERNAME: &str = "alice";
pub(super) const TEST_EMAIL: &str = "alice@example.com";

pub(super) async fn create_account(storage: &PostgresStorage) -> crate::Account {
    storage
        .get_or_create_account(TEST_ISSUER, TEST_USERNAME, TEST_EMAIL)
        .await
        .expect("create account")
}
