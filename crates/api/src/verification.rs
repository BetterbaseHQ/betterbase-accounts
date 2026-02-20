//! Verification code service: generate, send, and verify 6-digit codes.
//!
//! Mirrors Go `services/verification.go`.

use std::time::Duration;

use less_accounts_email::VerificationEmail;
use less_accounts_storage::{StorageError, VerificationCode, VerificationStorage};
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::AppState;

const VERIFICATION_CODE_EXPIRY: Duration = Duration::from_secs(10 * 60); // 10 minutes
pub const MAX_VERIFICATION_ATTEMPTS: i32 = 5;
pub const MAX_SENDS_PER_HOUR: i32 = 5;
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600); // 1 hour

/// Generate a cryptographically random 6-digit verification code.
fn generate_code() -> String {
    let n: u32 = OsRng.gen_range(0..1_000_000);
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
pub async fn verify_code(
    state: &AppState,
    email: &str,
    purpose: &str,
    code: &str,
) -> Result<Uuid, StorageError> {
    let record = state
        .storage
        .get_latest_verification_code_by_email(email, purpose)
        .await?;

    if record.attempts >= MAX_VERIFICATION_ATTEMPTS {
        let _ = state.storage.delete_verification_code(record.id).await;
        return Err(StorageError::VerificationMaxAttempts);
    }

    // Increment before checking (prevents timing attacks)
    state
        .storage
        .increment_verification_attempts(record.id)
        .await?;

    let expected = hash_code(code);
    if !constant_time_eq(&expected, &record.code_hash) {
        if record.attempts + 1 >= MAX_VERIFICATION_ATTEMPTS {
            let _ = state.storage.delete_verification_code(record.id).await;
        }
        return Err(StorageError::VerificationCodeNotFound);
    }

    let _ = state.storage.delete_verification_code(record.id).await;
    Ok(record.id)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
