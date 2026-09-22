//! Verification code service: generate, send, and verify 6-digit codes.
//!
//! Mirrors Go `services/verification.go`.

use std::time::Duration;

use betterbase_accounts_email::VerificationEmail;
use betterbase_accounts_storage::{
    ConsumeVerificationCode, StorageError, VerificationCode, VerificationStorage,
};
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::AppState;

const VERIFICATION_CODE_EXPIRY: Duration = Duration::from_secs(10 * 60); // 10 minutes
pub const MAX_VERIFICATION_ATTEMPTS: i32 = 5;
pub const MAX_SENDS_PER_HOUR: i32 = 5;
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600); // 1 hour

/// Generate a cryptographically random 6-digit verification code.
fn generate_code() -> String {
    let n: u32 = rand::rng().random_range(0..1_000_000);
    format!("{n:06}")
}

/// SHA-256 hash of a verification code string.
fn hash_code(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

/// Send a verification code to an email address.
pub async fn send_code(state: &AppState, email: &str, purpose: &str) -> Result<(), StorageError> {
    // Rate limit
    state
        .storage
        .check_and_increment_send_rate(
            email,
            MAX_SENDS_PER_HOUR,
            RATE_LIMIT_WINDOW,
            &state.identity_hash_key,
        )
        .await?;

    let code = generate_code();
    let code_hash = hash_code(&code);

    let now = chrono::Utc::now();
    let record = VerificationCode {
        id: Uuid::new_v4(),
        email: email.to_string(),
        code_hash,
        purpose: purpose.to_string(),
        attempts: 0,
        created_at: now,
        expires_at: now
            + chrono::Duration::from_std(VERIFICATION_CODE_EXPIRY).expect("valid duration"),
    };

    state.storage.create_verification_code(&record).await?;

    let email_msg = VerificationEmail {
        to: email.to_string(),
        code,
        purpose: purpose.to_string(),
    };

    state
        .mailer
        .send_verification_code(&email_msg)
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?;

    Ok(())
}

/// Verify a code for the given email and purpose.
///
/// Returns the verification code UUID on success (used as JTI for one-time-use tokens).
///
/// AUD-014: consumption is a single atomic storage operation — at most one
/// concurrent caller can succeed per issued code, and the 5-attempt bound
/// is enforced under a row lock rather than on a stale read snapshot.
pub async fn verify_code(
    state: &AppState,
    email: &str,
    purpose: &str,
    code: &str,
) -> Result<Uuid, StorageError> {
    let expected = hash_code(code);
    match state
        .storage
        .consume_verification_code(email, purpose, &expected, MAX_VERIFICATION_ATTEMPTS)
        .await?
    {
        ConsumeVerificationCode::Consumed(id) => Ok(id),
        ConsumeVerificationCode::Mismatch => Err(StorageError::VerificationCodeNotFound),
        ConsumeVerificationCode::Exhausted => Err(StorageError::VerificationMaxAttempts),
    }
}
