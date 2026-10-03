use super::*;

fn mailer() -> SmtpMailer {
    SmtpMailer::new(SmtpConfig {
        host: "smtp.example.test".into(),
        port: 587,
        username: String::new(),
        password: String::new(),
        from: "sender@example.test".into(),
    })
}
fn email(purpose: &str) -> VerificationEmail {
    VerificationEmail {
        to: "recipient@example.test".into(),
        code: "012345".into(),
        purpose: purpose.into(),
        expires_in: std::time::Duration::from_secs(600),
    }
}
#[test]
fn smtp_content_uses_the_code_lifetime_and_preserves_leading_zeroes() {
    for (purpose, subject) in [
        ("registration", "Your Less verification code"),
        ("recovery", "Your Less account recovery code"),
    ] {
        let mut email = email(purpose);
        for minutes in [10, 7] {
            email.expires_in = std::time::Duration::from_secs(minutes * 60);
            let rendered =
                String::from_utf8(mailer().build_message(&email).unwrap().formatted()).unwrap();
            assert!(rendered.contains(&format!("Subject: {subject}")));
            assert!(rendered.contains("To: recipient@example.test"));
            assert!(rendered.contains("From: sender@example.test"));
            assert!(rendered.contains("012345"));
            assert!(rendered.contains(&format!("expires in {minutes} minutes")));
        }
    }
}
#[tokio::test]
async fn invalid_addresses_fail_before_connecting_to_smtp() {
    let mut invalid = mailer();
    invalid.config.from = "not-an-address".into();
    assert!(matches!(
        invalid.send_verification_code(&email("registration")).await,
        Err(EmailError::InvalidAddress(_))
    ));
    let mut recipient = email("registration");
    recipient.to = "not-an-address".into();
    assert!(matches!(
        mailer().send_verification_code(&recipient).await,
        Err(EmailError::InvalidAddress(_))
    ));
}

#[tokio::test]
async fn smtp_rejection_is_reported_as_a_send_failure() {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut mailer = mailer();
    mailer.config.host = "127.0.0.1".into();
    mailer.config.port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket
            .write_all(b"421 service unavailable\r\n")
            .await
            .unwrap();
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        mailer.send_verification_code(&email("registration")),
    )
    .await;
    server.abort();
    assert!(matches!(
        result.expect("SMTP rejection must return promptly"),
        Err(EmailError::Send(_))
    ));
}
