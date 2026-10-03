use crate::test_support::{post_json, test_app, TEST_ISSUER};
use axum::http::StatusCode;
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine as _,
};
use betterbase_accounts_auth::{jwt::StatePurpose, opaque::test_registration_upload};
use betterbase_accounts_storage::{
    AccountStorage, RecoveryStorage, RegistrationState, RegistrationStateStorage, StorageError,
};
use serde_json::{json, Value};

const STORE: &str = "/v1/accounts/recovery-blob";

#[tokio::test]
async fn recovery_and_rotation_cannot_bypass_blob_validation() {
    let Some(app) = test_app().await else { return };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let original_upload =
        test_registration_upload(&app.opaque, b"original", account.id.as_bytes()).unwrap();
    let original_record = app.opaque.registration_finish(&original_upload).unwrap();
    app.storage
        .finalize_registration_with_root_key(account.id, &original_record, &[1; 41])
        .await
        .unwrap();
    let original_blob = blob(1).to_string();
    app.storage
        .store_recovery_blob(account.id, original_blob.as_bytes())
        .await
        .unwrap();
    let auth = app.auth_token(&account.id.to_string());
    let replacement =
        test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
    let mut invalid = blob(2);
    invalid["iv"] = Value::Null;
    for path in [
        "/v1/accounts/recover/finalize",
        "/v1/accounts/rotate-root-key",
    ] {
        let mut bad_blobs = vec![
            b"not JSON".to_vec(),
            b"{}".to_vec(),
            invalid.to_string().into_bytes(),
        ];
        if path.ends_with("rotate-root-key") {
            bad_blobs.push(vec![0xff]);
        }
        for bad_blob in bad_blobs {
            let body = if path.ends_with("rotate-root-key") {
                json!({"wrapped_root_key": B64.encode([2; 41]), "expected_root_version": 0,
                    "grants": [], "recovery_blob": B64.encode(bad_blob)})
            } else {
                let id = uuid::Uuid::new_v4();
                let now = chrono::Utc::now();
                app.storage
                    .create_registration_state(&RegistrationState {
                        id,
                        account_id: account.id,
                        username: account.username.clone(),
                        root_key_version: 0,
                        created_at: now,
                        expires_at: now + chrono::Duration::seconds(60),
                    })
                    .await
                    .unwrap();
                let token = app
                    .jwt
                    .create_state_token(&id.to_string(), StatePurpose::Recovery, 0)
                    .unwrap();
                json!({"state_token": token, "opaque_record": B64.encode(&replacement),
                    "wrapped_root_key": B64.encode([2; 41]), "new_blob": String::from_utf8(bad_blob).unwrap()})
            };
            let (status, error) = post_json(&app, path, Some(&auth), &body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {error}");
            let current = app.storage.get_account_by_id(account.id).await.unwrap();
            assert_eq!(
                current.opaque_record.as_deref(),
                Some(original_record.as_slice())
            );
            assert_eq!(current.wrapped_root_key, Some(vec![1; 41]));
            assert_eq!(current.credentials_version, 0);
            assert_eq!(current.root_key_version, 0);
            assert_eq!(
                app.storage
                    .get_recovery_blob_by_email(TEST_ISSUER, &account.email)
                    .await
                    .unwrap(),
                original_blob.as_bytes()
            );
        }
    }
    // Control: a fresh recovery exchange atomically installs a valid replacement.
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    app.storage
        .create_registration_state(&RegistrationState {
            id,
            account_id: account.id,
            username: account.username.clone(),
            root_key_version: 0,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        })
        .await
        .unwrap();
    let token = app
        .jwt
        .create_state_token(&id.to_string(), StatePurpose::Recovery, 0)
        .unwrap();
    let new_blob = blob(2).to_string();
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/finalize",
        None,
        &json!({"state_token": token, "opaque_record": B64.encode(replacement),
            "wrapped_root_key": B64.encode([2; 41]), "new_blob": new_blob}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let current = app.storage.get_account_by_id(account.id).await.unwrap();
    assert_eq!(current.credentials_version, 1);
    assert_eq!(current.root_key_version, 1);
    assert_eq!(current.wrapped_root_key, Some(vec![2; 41]));
    assert_eq!(
        app.storage
            .get_recovery_blob_by_email(TEST_ISSUER, &account.email)
            .await
            .unwrap(),
        new_blob.as_bytes()
    );
}

fn blob(byte: u8) -> Value {
    json!({"version": 2, "alg": "A256GCM", "iv": B64URL.encode([byte; 12]),
        "ciphertext": B64URL.encode([byte; 48])})
}

#[tokio::test]
async fn recovery_blob_upload_requires_an_auth_session() {
    let Some(app) = test_app().await else { return };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let verification = app
        .jwt
        .create_verification_token(&account.email, "recovery")
        .unwrap();
    for token in [None, Some("invalid"), Some(verification.as_str())] {
        let (status, body) =
            post_json(&app, STORE, token, &json!({"blob": blob(1).to_string()})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(matches!(
            app.storage
                .get_recovery_blob_by_email(TEST_ISSUER, &account.email)
                .await,
            Err(StorageError::RecoveryBlobNotFound)
        ));
    }
}

#[tokio::test]
async fn recovery_blob_replacement_is_scoped_to_the_authenticated_account() {
    let Some(app) = test_app().await else { return };
    let alice = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let bob = app
        .storage
        .get_or_create_account(TEST_ISSUER, "bob", "bob@example.test")
        .await
        .unwrap();
    for (account, value) in [(&alice, blob(1)), (&bob, blob(2)), (&alice, blob(3))] {
        let encoded = value.to_string();
        let auth = app.auth_token(&account.id.to_string());
        let (status, body) = post_json(
            &app,
            STORE,
            Some(&auth),
            &json!({"blob": encoded, "account_id": bob.id, "email": bob.email}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(
            app.storage
                .get_recovery_blob_by_email(TEST_ISSUER, &account.email)
                .await
                .unwrap(),
            encoded.as_bytes()
        );
        let verification = app
            .jwt
            .create_verification_token(&account.email, "recovery")
            .unwrap();
        let (status, fetched) = post_json(
            &app,
            "/v1/accounts/recovery-blob/fetch",
            Some(&verification),
            &json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{fetched}");
        assert_eq!(fetched["blob"], encoded);
        assert_eq!(fetched["root_key_version"], 0);
    }
    assert_eq!(
        app.storage
            .get_recovery_blob_by_email(TEST_ISSUER, &bob.email)
            .await
            .unwrap(),
        blob(2).to_string().as_bytes()
    );
}

#[tokio::test]
async fn malformed_recovery_blobs_cannot_replace_a_valid_blob() {
    let Some(app) = test_app().await else { return };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .unwrap();
    let auth = app.auth_token(&account.id.to_string());
    let original = blob(1).to_string();
    assert_eq!(
        post_json(&app, STORE, Some(&auth), &json!({"blob": original}))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let mut invalid = vec!["not json".into(), "null".into(), "[]".into(), "{}".into()];
    for field in ["version", "alg", "iv", "ciphertext"] {
        let mut value = blob(2);
        value.as_object_mut().unwrap().remove(field);
        invalid.push(value.to_string());
        for replacement in [Value::Null, json!(false), json!(123), json!([]), json!({})] {
            let mut value = blob(2);
            value[field] = replacement;
            invalid.push(value.to_string());
        }
    }
    for (field, replacement) in [
        ("version", json!(1)),
        ("alg", json!("A128GCM")),
        ("iv", json!("!")),
        ("iv", json!("")),
        ("iv", json!(B64URL.encode([0; 11]))),
        ("iv", json!(B64URL.encode([0; 13]))),
        ("ciphertext", json!("!")),
        ("ciphertext", json!("")),
        ("ciphertext", json!(B64URL.encode([0; 47]))),
        ("ciphertext", json!(B64URL.encode([0; 49]))),
    ] {
        let mut value = blob(2);
        value[field] = replacement;
        invalid.push(value.to_string());
    }
    for encoded in invalid {
        let (status, body) = post_json(&app, STORE, Some(&auth), &json!({"blob": encoded})).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "accepted {encoded}: {body}"
        );
        assert_eq!(
            app.storage
                .get_recovery_blob_by_email(TEST_ISSUER, &account.email)
                .await
                .unwrap(),
            original.as_bytes()
        );
    }
}
