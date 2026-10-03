use super::*;
use axum::{http::StatusCode, routing::post, Json, Router};

fn config(url: String, enabled: bool) -> CapConfig {
    CapConfig {
        enabled,
        verify_url: url,
        key_id: "site-id".into(),
        secret: "server-secret".into(),
    }
}

#[tokio::test]
async fn disabled_verification_and_missing_tokens_do_not_require_a_server() {
    let disabled = CapService::new(config("http://127.0.0.1:1".into(), false));
    disabled.verify("").await.unwrap();
    disabled.verify("anything").await.unwrap();
    let enabled = CapService::new(config("http://127.0.0.1:1".into(), true));
    assert!(matches!(
        enabled.verify("").await,
        Err(CapError::TokenMissing)
    ));
}

#[tokio::test]
async fn verification_fails_closed_on_rejection_http_errors_and_invalid_responses() {
    for (status, body, expected) in [
        (StatusCode::OK, r#"{"success":true}"#, "ok"),
        (
            StatusCode::OK,
            r#"{"success":false,"error":"expired"}"#,
            "invalid",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"success":true}"#,
            "service",
        ),
        (StatusCode::OK, "not json", "service"),
        (StatusCode::OK, "{}", "service"),
    ] {
        let (sent, received) = tokio::sync::oneshot::channel();
        let sent = std::sync::Arc::new(tokio::sync::Mutex::new(Some(sent)));
        let router = Router::new().route(
            "/site-id/siteverify",
            post(move |Json(request): Json<serde_json::Value>| async move {
                sent.lock().await.take().unwrap().send(request).unwrap();
                (status, body)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service = CapService::new(config(
            format!("http://{}", listener.local_addr().unwrap()),
            true,
        ));
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let result = service.verify("proof").await;
        server.abort();
        assert_eq!(
            received.await.unwrap(),
            serde_json::json!({"secret": "server-secret", "response": "proof"})
        );
        match expected {
            "ok" => result.unwrap(),
            "invalid" => assert!(matches!(result, Err(CapError::TokenInvalid))),
            _ => assert!(matches!(result, Err(CapError::ServiceError(_)))),
        }
    }
}
