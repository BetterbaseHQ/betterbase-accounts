use super::*;
use std::{collections::HashMap, env::VarError, sync::OnceLock};

fn environment() -> HashMap<String, String> {
    static SETUP: OnceLock<String> = OnceLock::new();
    [
        (
            "DATABASE_URL",
            "postgres://accounts:password@localhost/test".into(),
        ),
        (
            "OPAQUE_SERVER_SETUP",
            SETUP
                .get_or_init(OpaqueService::generate_server_setup_hex)
                .clone(),
        ),
        ("OAUTH_ISSUER", "https://accounts.example.test".into()),
        ("IDENTITY_HASH_KEY", "ab".repeat(32)),
        ("SMTP_DEV_MODE", "true".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}
fn load(values: &HashMap<String, String>) -> Result<AppConfig> {
    AppConfig::from_lookup(|key| values.get(key).cloned().ok_or(VarError::NotPresent))
}

#[test]
fn minimal_environment_has_documented_defaults() {
    let config = load(&environment()).unwrap();
    assert_eq!(config.listen_addr, "0.0.0.0:5377");
    assert_eq!(config.smtp_port, 587);
    assert_eq!(config.smtp_from, "noreply@betterbase.dev");
    assert_eq!(config.log_format, "text");
    assert_eq!(config.cap_verify_url, "http://cap:3000");
    assert!(!config.cap_enabled);
    assert!(config.accounts_public_url.is_none());
    assert!(config.sync_endpoint.is_none());
    assert!(config.federation_ws_endpoint.is_none());
}

#[test]
fn required_variables_reject_absence_and_whitespace_without_leaking_values() {
    for name in [
        "DATABASE_URL",
        "OPAQUE_SERVER_SETUP",
        "OAUTH_ISSUER",
        "IDENTITY_HASH_KEY",
    ] {
        for replacement in [None, Some(""), Some(" \t ")] {
            let mut values = environment();
            values.remove(name);
            if let Some(value) = replacement {
                values.insert(name.into(), value.into());
            }
            let error = format!(
                "{:#}",
                load(&values).err().expect("must reject invalid config")
            );
            assert!(error.contains(name), "{error}");
            assert!(!error.contains("accounts:password"));
        }
    }
}

#[test]
fn malformed_secrets_are_rejected_before_startup() {
    for (name, bad) in [
        ("IDENTITY_HASH_KEY", "zz".repeat(32)),
        ("IDENTITY_HASH_KEY", "aa".repeat(31)),
        ("IDENTITY_HASH_KEY", "aa".repeat(33)),
        ("IDENTITY_HASH_KEY", "a".repeat(63)),
        ("OPAQUE_SERVER_SETUP", "not-hex-secret".into()),
        ("OPAQUE_SERVER_SETUP", "00".into()),
    ] {
        let mut values = environment();
        values.insert(name.into(), bad.clone());
        let error = format!("{:#}", load(&values).err().expect("invalid secret"));
        assert!(error.contains(name), "{error}");
        assert!(!error.contains(&bad), "secret leaked in diagnostic");
    }
}

#[test]
fn invalid_listeners_ports_and_issuer_urls_are_rejected() {
    for (name, bad) in [
        ("LISTEN_ADDR", "localhost:5377"),
        ("LISTEN_ADDR", "127.0.0.1:99999"),
        ("SMTP_PORT", "abc"),
        ("SMTP_PORT", "-1"),
        ("SMTP_PORT", "65536"),
        ("SMTP_PORT", "0"),
        ("OAUTH_ISSUER", "not-a-url"),
        ("OAUTH_ISSUER", "ftp://accounts.test"),
        ("OAUTH_ISSUER", "https://user:secret@accounts.test"),
        ("OAUTH_ISSUER", "https://accounts.test?q=1"),
        ("OAUTH_ISSUER", "https://accounts.test#fragment"),
    ] {
        let mut values = environment();
        values.insert(name.into(), bad.into());
        let error = format!("{:#}", load(&values).err().expect("invalid config"));
        assert!(error.contains(name), "{name}={bad}: {error}");
    }
}

#[test]
fn cap_configuration_requires_credentials_only_when_enabled() {
    let mut values = environment();
    values.insert("CAP_VERIFY_URL".into(), "invalid".into());
    assert!(load(&values).is_ok(), "disabled CAP needs no configuration");
    values.insert("CAP_KEY_ID".into(), "site-id".into());
    assert!(load(&values)
        .err()
        .unwrap()
        .to_string()
        .contains("CAP_SECRET"));
    values.insert("CAP_SECRET".into(), "secret".into());
    assert!(format!("{:#}", load(&values).err().unwrap()).contains("CAP_VERIFY_URL"));
    values.insert("CAP_VERIFY_URL".into(), "http://cap:3000".into());
    let config = load(&values).unwrap();
    assert!(config.cap_enabled);
    assert_eq!(config.cap_key_id, "site-id");
}

#[test]
fn smtp_and_public_url_overrides_are_loaded_and_normalized() {
    let mut values = environment();
    values.remove("SMTP_DEV_MODE");
    assert!(load(&values)
        .err()
        .unwrap()
        .to_string()
        .contains("SMTP_HOST"));
    for (key, value) in [
        ("SMTP_HOST", "smtp.example.test"),
        ("SMTP_PORT", "2525"),
        ("SMTP_USERNAME", "sender"),
        ("SMTP_PASSWORD", "secret"),
        ("SMTP_FROM", "sender@example.test"),
        ("ACCOUNTS_PUBLIC_URL", " https://Accounts.Example.Test/ "),
        ("LISTEN_ADDR", "[::1]:5377"),
        ("SYNC_ENDPOINT", "https://sync.test"),
        ("FEDERATION_WS_ENDPOINT", "wss://sync.test"),
        ("WEB_BASE_URL", "https://ui.test"),
        ("LOG_FORMAT", "json"),
    ] {
        values.insert(key.into(), value.into());
    }
    let config = load(&values).unwrap();
    assert!(!config.smtp_dev_mode);
    assert_eq!(config.smtp_port, 2525);
    assert_eq!(config.smtp_username, "sender");
    assert_eq!(config.smtp_password, "secret");
    assert_eq!(config.smtp_from, "sender@example.test");
    assert_eq!(
        config.accounts_public_url.as_deref(),
        Some("https://accounts.example.test")
    );
    assert_eq!(config.sync_endpoint.as_deref(), Some("https://sync.test"));
    assert_eq!(
        config.federation_ws_endpoint.as_deref(),
        Some("wss://sync.test")
    );
    assert_eq!(config.web_base_url, "https://ui.test");
    assert_eq!(config.log_format, "json");
}

#[tokio::test]
async fn direct_startup_validates_secrets_before_touching_the_database() {
    let mut config = load(&environment()).unwrap();
    config.database_url = "invalid-database-url".into();
    config.identity_hash_key = "invalid-secret".into();
    let error = run(config).await.unwrap_err().to_string();
    assert!(error.contains("IDENTITY_HASH_KEY"), "{error}");
}

#[test]
fn issuer_paths_require_a_separate_discovery_base() {
    let mut values = environment();
    values.insert(
        "OAUTH_ISSUER".into(),
        "https://identity.example.test/accounts".into(),
    );
    assert!(format!("{:#}", load(&values).err().unwrap()).contains("ACCOUNTS_PUBLIC_URL"));
    values.insert(
        "ACCOUNTS_PUBLIC_URL".into(),
        "https://api.example.test".into(),
    );
    let config = load(&values).unwrap();
    assert_eq!(
        config.oauth_issuer,
        "https://identity.example.test/accounts"
    );
    assert_eq!(
        config.accounts_public_url.as_deref(),
        Some("https://api.example.test")
    );
}

#[test]
fn direct_config_cannot_enable_cap_without_a_key_id() {
    let mut config = load(&environment()).unwrap();
    config.cap_enabled = true;
    config.cap_secret = "secret".into();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("CAP_KEY_ID"));
    config.cap_key_id = "site-id".into();
    config.validate().unwrap();
}
