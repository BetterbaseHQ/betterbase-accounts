use betterbase_accounts_storage::{postgres::PostgresStorage, OAuthClientStorage};
use std::process::{Command, Output};

fn cli(args: &[&str], database: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_betterbase-accounts-oauth-client"));
    command.args(args).env_remove("DATABASE_URL");
    if let Some(url) = database {
        command.env("DATABASE_URL", url);
    }
    command.output().expect("run CLI")
}
fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn help_and_command_errors_do_not_require_a_database() {
    for help in ["help", "--help", "-h"] {
        let output = cli(&[help], None);
        assert!(output.status.success());
        assert!(stdout(&output).contains("Usage:"));
    }
    for args in [vec![], vec!["unknown"], vec!["list", "--unexpected"]] {
        let output = cli(&args, None);
        assert!(!output.status.success());
        assert!(
            !stderr(&output).contains("DATABASE_URL"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn create_rejects_invalid_arguments_before_connecting() {
    for (args, message) in [
        (vec!["create"], "--name is required"),
        (vec!["create", "--name"], "--name requires a value"),
        (
            vec!["create", "--name", "--redirect-uri", "https://example.test"],
            "--name requires a value",
        ),
        (
            vec![
                "create",
                "--name",
                "   ",
                "--redirect-uri",
                "https://example.test",
            ],
            "--name is required",
        ),
        (
            vec!["create", "--name", "app"],
            "at least one --redirect-uri",
        ),
        (
            vec!["create", "--redirect-uri"],
            "--redirect-uri requires a value",
        ),
        (vec!["create", "--scope"], "--scope requires a value"),
        (vec!["create", "--scope", "invalid"], "invalid scope"),
        (vec!["create", "--unknown"], "unknown flag"),
    ] {
        let output = cli(&args, None);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains(message),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    for uri in [
        "https://",
        "https://example.test/#fragment",
        "https://user:password@example.test/cb",
        "javascript:alert(1)",
        "https://exa mple.test",
        " https://example.test",
    ] {
        let output = cli(&["create", "--name", "app", "--redirect-uri", uri], None);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("redirect URI"),
            "{uri}: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("DATABASE_URL"));
    }
}

#[test]
fn database_configuration_errors_are_actionable() {
    let output = cli(&["list"], None);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("DATABASE_URL is required"));
    let output = cli(&["list"], Some("invalid-database-url"));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("failed to connect to database"));
}

async fn database() -> Option<(String, PostgresStorage)> {
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
    let url = url.to_string();
    let storage = PostgresStorage::connect_and_migrate(&url).await.unwrap();
    pool.close().await;
    Some((url, storage))
}

#[tokio::test]
async fn create_and_list_round_trip_clients_without_merging_duplicate_names() {
    let Some((url, storage)) = database().await else {
        return;
    };
    let output = cli(&["list"], Some(&url));
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("No OAuth clients registered"));
    for scopes in [
        vec![],
        vec![
            "--scope",
            "sync",
            "--scope",
            "files",
            "--scope",
            "inference",
            "--scope",
            "keys",
        ],
    ] {
        let mut args = vec![
            "create",
            "--name",
            "Same Name",
            "--redirect-uri",
            "http://localhost:5381/callback",
            "--redirect-uri",
            "https://example.test/callback?source=app",
        ];
        args.extend(scopes);
        let output = cli(&args, Some(&url));
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        let id = text
            .lines()
            .find_map(|line| line.strip_prefix("Client ID:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let stored = storage.get_oauth_client(id).await.unwrap();
        assert_eq!(stored.name, "Same Name");
        assert!(stored.secret_hash.is_none());
        assert_eq!(
            stored.redirect_uris,
            vec![
                "http://localhost:5381/callback",
                "https://example.test/callback?source=app"
            ]
        );
        if args.contains(&"--scope") {
            assert_eq!(
                stored.allowed_scopes,
                vec!["sync", "files", "inference", "keys"]
            );
        } else {
            assert!(stored.allowed_scopes.is_empty());
            assert!(text.contains("OIDC only"));
        }
    }
    let output = cli(&["list"], Some(&url));
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Total: 2 client(s)"));
    assert_eq!(stdout(&output).matches("Same Name").count(), 2);
    assert!(stdout(&output).contains("sync, files, inference, keys"));
    // A server-side write failure must return failure, never a success message.
    sqlx::query("ALTER TABLE oauth_clients ADD CONSTRAINT reject_new CHECK (name = 'Same Name')")
        .execute(storage.pool())
        .await
        .unwrap();
    let output = cli(
        &[
            "create",
            "--name",
            "Rejected",
            "--redirect-uri",
            "https://example.test",
        ],
        Some(&url),
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("failed to create OAuth client"));
    assert!(!stdout(&output).contains("successfully"));
    storage.pool().close().await;
}

#[test]
fn redirects_require_an_explicit_http_authority() {
    for uri in [
        "https:example.test/callback",
        "http:example.test/callback",
        "https:/example.test/callback",
        "https:///example.test/callback",
        "//example.test/callback",
        r"https:\example.test/callback",
        r"https://example.test\callback",
    ] {
        let output = cli(&["create", "--name", "app", "--redirect-uri", uri], None);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("redirect URI"),
            "{uri}: {}",
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains("DATABASE_URL"),
            "{uri} must fail before connecting"
        );
    }
    for uri in [
        "https://example.test/callback?source=app",
        "http://localhost:5381/callback",
        "HTTPS://example.test/callback",
        "http://[::1]:5381/callback",
    ] {
        let output = cli(&["create", "--name", "app", "--redirect-uri", uri], None);
        assert!(
            stderr(&output).contains("DATABASE_URL is required"),
            "valid URL rejected: {uri}: {}",
            stderr(&output)
        );
    }
}
