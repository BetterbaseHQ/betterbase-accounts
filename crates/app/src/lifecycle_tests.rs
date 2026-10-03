use super::*;
use betterbase_accounts_storage::StorageError;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Default)]
struct CleanupProbe {
    calls: Mutex<Vec<usize>>,
    fail: AtomicUsize,
}
impl CleanupProbe {
    fn record(&self, step: usize) -> Result<(), StorageError> {
        self.calls.lock().unwrap().push(step);
        if self.fail.load(Ordering::SeqCst) == step {
            Err(StorageError::Internal("injected cleanup failure".into()))
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait]
impl CleanupStorage for CleanupProbe {
    async fn cleanup_expired_states(&self) -> Result<(), StorageError> {
        self.record(1)
    }
    async fn cleanup_expired_oauth_codes(&self) -> Result<(), StorageError> {
        self.record(2)
    }
    async fn cleanup_expired_refresh_tokens(&self) -> Result<(), StorageError> {
        self.record(3)
    }
    async fn cleanup_used_refresh_tokens(&self, age: Duration) -> Result<(), StorageError> {
        assert_eq!(age, Duration::from_secs(7 * 86400));
        self.record(4)
    }
    async fn cleanup_expired_verification_codes(&self) -> Result<(), StorageError> {
        self.record(5)
    }
    async fn cleanup_expired_verification_tokens(&self) -> Result<(), StorageError> {
        self.record(6)
    }
    async fn cleanup_unregistered_accounts(&self, age: Duration) -> Result<(), StorageError> {
        assert_eq!(age, Duration::from_secs(7 * 86400));
        self.record(7)
    }
}

#[tokio::test]
async fn cleanup_continues_after_each_failure_and_retries_next_cycle() {
    for failed in 1..=7 {
        let probe = CleanupProbe::default();
        probe.fail.store(failed, Ordering::SeqCst);
        cleanup_once(&probe).await;
        probe.fail.store(0, Ordering::SeqCst);
        cleanup_once(&probe).await;
        assert_eq!(
            *probe.calls.lock().unwrap(),
            (1..=7).chain(1..=7).collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn shutdown_and_cancellation_release_cleanup_workers() {
    for cancel in [false, true] {
        let probe = Arc::new(CleanupProbe::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let (send, receive) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve_with_cleanup(listener, router, probe.clone(), async {
            let _ = receive.await;
        }));
        assert_eq!(
            reqwest::get(format!("http://{address}/health"))
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "ok"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while probe.calls.lock().unwrap().len() < 7 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            send.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&probe) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup worker must release storage on exit");
    }
}

async fn database_config() -> Option<(AppConfig, sqlx::PgPool)> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            assert_ne!(
                std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref(),
                Some("1"),
                "DATABASE_URL required"
            );
            return None;
        }
    };
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    let mut url = url::Url::parse(&url).unwrap();
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let mut config = super::tests::test_config();
    config.database_url = url.to_string();
    Some((config, pool))
}

#[tokio::test]
async fn startup_migrates_bootstraps_and_serves_real_routes_then_stops() {
    let Some((config, admin)) = database_config().await else {
        return;
    };
    let (router, storage) = build_app(&config).await.unwrap();
    assert_eq!(storage.list_signing_keys().await.unwrap().len(), 1);
    let first_key = storage.get_current_jwt_key().await.unwrap().id;
    let (_, restarted) = build_app(&config).await.unwrap();
    assert_eq!(restarted.get_current_jwt_key().await.unwrap().id, first_key);
    assert_eq!(restarted.list_signing_keys().await.unwrap().len(), 1);
    restarted.pool().close().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(serve_with_cleanup(
        listener,
        router,
        storage.clone(),
        async {
            let _ = receive.await;
        },
    ));
    let health = reqwest::get(format!("http://{address}/health"))
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(health.headers()["x-protocol-version"], "1");
    let jwks: serde_json::Value = reqwest::get(format!("http://{address}/.well-known/jwks.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    assert_eq!(jwks["keys"][0]["kty"], "EC");
    send.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(Arc::strong_count(&storage), 1);
    storage.pool().close().await;
    admin.close().await;
}

#[tokio::test]
async fn occupied_port_fails_without_starting_a_cleanup_worker() {
    let Some((mut config, admin)) = database_config().await else {
        return;
    };
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.listen_addr = occupied.local_addr().unwrap().to_string();
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        run_until(config, std::future::pending()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("failed to bind"));
    admin.close().await;
}

#[tokio::test]
async fn graceful_shutdown_drains_an_in_flight_request() {
    let probe = Arc::new(CleanupProbe::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let router = axum::Router::new().route(
        "/slow",
        axum::routing::get({
            let entered = entered.clone();
            let release = release.clone();
            move || {
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    "completed"
                }
            }
        }),
    );
    let (send, receive) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(serve_with_cleanup(listener, router, probe.clone(), async {
        let _ = receive.await;
    }));
    let request = tokio::spawn(async move {
        reqwest::get(format!("http://{address}/slow"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    send.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut server)
            .await
            .is_err(),
        "shutdown must wait for the active request"
    );
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), request)
            .await
            .unwrap()
            .unwrap(),
        "completed"
    );
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(Arc::strong_count(&probe), 1);
}
