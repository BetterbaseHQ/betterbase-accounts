//! Route-level test harness: a real router over a throwaway PostgreSQL schema.
//!
//! Skips without `DATABASE_URL`; panics when `BB_TEST_REQUIRE_DB=1` (set by
//! `just test-db` and CI) so an unreachable database fails the gate.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use betterbase_accounts_auth::{es256::generate_keypair, jwt::JwtService, opaque::OpaqueService};
use betterbase_accounts_cap::{CapConfig, CapService};
use betterbase_accounts_email::DevMailer;
use betterbase_accounts_storage::postgres::PostgresStorage;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use crate::state::{ApiConfig, AppState};

pub(crate) const TEST_ISSUER: &str = "https://accounts.example.test";

pub(crate) struct TestApp {
    pub router: Router,
    pub storage: Arc<PostgresStorage>,
    pub jwt: Arc<JwtService>,
}

impl TestApp {
    /// Mint a bearer auth token for an account id.
    pub(crate) fn auth_token(&self, account_id: &str) -> String {
        self.jwt.create_auth_token(account_id).expect("auth token")
    }
}

pub(crate) async fn test_app() -> Option<TestApp> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => {
            if std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref() == Some("1") {
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
    sqlx::migrate!("../storage/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let storage = Arc::new(PostgresStorage::new(pool));

    let (es256_private, es256_public) = generate_keypair().expect("ES256 keypair");
    let jwt = Arc::new(JwtService::new(
        1,
        vec![0x42; 32],
        1,
        es256_private,
        vec![(1, es256_public)],
        TEST_ISSUER.to_owned(),
    ));
    let opaque = Arc::new(
        OpaqueService::from_hex(&OpaqueService::generate_server_setup_hex())
            .expect("opaque service"),
    );
    let cap = Arc::new(CapService::new(CapConfig {
        enabled: false,
        verify_url: "http://cap.invalid".to_owned(),
        key_id: String::new(),
        secret: String::new(),
    }));

    let identity_domain = "accounts.example.test".to_owned();
    let config = Arc::new(ApiConfig {
        issuer: TEST_ISSUER.to_owned(),
        identity_domain,
        sync_endpoint: None,
        federation_ws_endpoint: None,
        web_base_url: "https://accounts.example.test".to_owned(),
        cap_enabled: false,
    });

    let state = AppState {
        storage: storage.clone(),
        jwt: jwt.clone(),
        opaque,
        cap,
        mailer: Arc::new(DevMailer),
        config,
        identity_hash_key: vec![0x11; 32],
    };

    Some(TestApp {
        router: crate::build_router(state),
        storage,
        jwt,
    })
}

/// GET a URI, optionally with a bearer token; return status and body.
pub(crate) async fn get_json(
    app: &TestApp,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let request = builder.body(Body::empty()).expect("build request");
    let response = app.router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("parse json body")
    };
    (status, json)
}

/// POST a JSON body, optionally with a bearer token; return status and body.
pub(crate) async fn post_json(
    app: &TestApp,
    uri: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let request = builder
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize body"),
        ))
        .expect("build request");
    let response = app.router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("parse json body")
    };
    (status, json)
}

/// POST a form-encoded body, optionally with a bearer token; return status and body.
pub(crate) async fn post_form(
    app: &TestApp,
    uri: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("build request");
    let response = app.router.clone().oneshot(request).await.expect("dispatch");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("parse json body")
    };
    (status, json)
}
