use super::*;

pub(super) fn test_config() -> AppConfig {
    AppConfig {
        database_url: "postgres://test".to_string(),
        opaque_server_setup: OpaqueService::generate_server_setup_hex(),
        oauth_issuer: "https://accounts.test".to_string(),
        accounts_public_url: None,
        identity_hash_key: "aa".repeat(32),
        listen_addr: "127.0.0.1:5377".to_string(),
        sync_endpoint: None,
        federation_ws_endpoint: None,
        web_base_url: String::new(),
        log_format: "text".to_string(),
        cap_enabled: false,
        cap_key_id: String::new(),
        cap_secret: String::new(),
        cap_verify_url: "http://cap:3000".to_string(),
        smtp_dev_mode: true,
        smtp_host: String::new(),
        smtp_port: 587,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_from: "noreply@test".to_string(),
    }
}

#[test]
fn smtp_mode_requires_host() {
    let mut config = test_config();
    config.smtp_dev_mode = false;
    config.smtp_host = String::new();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("SMTP_HOST"), "unexpected error: {err}");
}

#[test]
fn smtp_mode_accepts_host() {
    let mut config = test_config();
    config.smtp_dev_mode = false;
    config.smtp_host = "smtp.example.com".to_string();
    config.validate().expect("host set in SMTP mode is valid");
}

#[test]
fn dev_mailer_mode_allows_empty_host() {
    let mut config = test_config();
    config.smtp_dev_mode = true;
    config.smtp_host = String::new();
    config.validate().expect("dev mailer needs no host");
}

#[test]
fn accounts_public_url_defaults_to_unset_and_validates_shape() {
    let mut config = test_config();
    config
        .validate()
        .expect("unset ACCOUNTS_PUBLIC_URL (issuer-hosted) is valid");

    config.accounts_public_url = Some("https://accounts.test".to_string());
    config.validate().expect("bare base URL is valid");

    for bad in [
        "",
        "accounts.test",
        "https://accounts.test/v1",
        "https://accounts.test/?x=1",
        "https://accounts.test#f",
        "https://u:p@accounts.test",
        "https://@accounts.test",
        "file://accounts.test",
        // valid shapes that must pass through from_env normalization
        // before reaching AppConfig, never be stored raw
        "https://accounts.test/",
        " https://accounts.test ",
        "HTTPS://ACCOUNTS.TEST",
        "https://accounts.test:",
    ] {
        config.accounts_public_url = Some(bad.to_string());
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("ACCOUNTS_PUBLIC_URL"),
            "unexpected error for {bad:?}: {err}"
        );
    }
}

#[test]
fn accounts_public_url_env_values_are_normalized() {
    assert_eq!(
        AppConfig::normalize_public_url("https://accounts.test").unwrap(),
        "https://accounts.test"
    );
    // trailing slash, padding, mixed case, and empty port all canonicalize
    assert_eq!(
        AppConfig::normalize_public_url(" https://Accounts.Test/ ").unwrap(),
        "https://accounts.test"
    );
    assert_eq!(
        AppConfig::normalize_public_url("https://accounts.test:").unwrap(),
        "https://accounts.test"
    );
    for bad in [
        "",
        "accounts.test",
        "https://accounts.test/v1",
        "https://accounts.test?q",
        "https://accounts.test#f",
        "https://u:p@accounts.test",
        "file://accounts.test",
    ] {
        assert!(
            AppConfig::normalize_public_url(bad).is_err(),
            "expected rejection: {bad:?}"
        );
    }
}
