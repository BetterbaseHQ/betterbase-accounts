#![forbid(unsafe_code)]
//! Email delivery: trait + SMTP and dev-mode implementations.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("failed to send email: {0}")]
    Send(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

/// Verification email content.
pub struct VerificationEmail {
    pub to: String,
    pub code: String,
    pub purpose: String,
}

/// Mailer trait — send a verification code email.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send_verification_code(&self, email: &VerificationEmail) -> Result<(), EmailError>;
}

// ─── SMTP mailer ─────────────────────────────────────────────────────────────

/// Configuration for SMTP delivery.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}

/// Production SMTP mailer using lettre.
pub struct SmtpMailer {
    config: SmtpConfig,
}

impl SmtpMailer {
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send_verification_code(&self, email: &VerificationEmail) -> Result<(), EmailError> {
        use lettre::{
            message::header::ContentType, transport::smtp::authentication::Credentials,
            AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
        };

        let subject = match email.purpose.as_str() {
            "registration" => "Your Less verification code",
            "recovery" => "Your Less account recovery code",
            _ => "Your Less verification code",
        };

        let body = format!(
            "Your verification code is: {}\n\nThis code expires in 15 minutes.",
            email.code
        );

        let message = Message::builder()
            .from(
                self.config
                    .from
                    .parse()
                    .map_err(|e| EmailError::InvalidAddress(format!("{e}")))?,
            )
            .to(email
                .to
                .parse()
                .map_err(|e| EmailError::InvalidAddress(format!("{e}")))?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| EmailError::Send(e.to_string()))?;

        let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.host)
            .map_err(|e| EmailError::Send(e.to_string()))?
            .port(self.config.port)
            .credentials(creds)
            .build();

        transport
            .send(message)
            .await
            .map_err(|e| EmailError::Send(e.to_string()))?;

        Ok(())
    }
}

// ─── Dev mailer (logs instead of sending) ───────────────────────────────────

/// Development mailer — logs emails to stdout, never actually sends.
pub struct DevMailer;

#[async_trait]
impl Mailer for DevMailer {
    async fn send_verification_code(&self, email: &VerificationEmail) -> Result<(), EmailError> {
        // Print in the same format as the Go server's DevMode so e2e tests
        // can extract verification codes from Docker container logs.
        let subject = match email.purpose.as_str() {
            "recovery" => "Your password reset code",
            _ => "Your verification code",
        };
        println!("\n========== EMAIL PREVIEW ==========");
        println!("To: {}", email.to);
        println!("Subject: {subject}");
        println!("-----------------------------------");
        println!("Your verification code is: {}", email.code);
        println!("\nThis code will expire in 10 minutes.");
        println!("\nIf you didn't request this code, you can safely ignore this email.");
        println!("===================================");
        Ok(())
    }
}
