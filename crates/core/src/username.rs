//! Username validation and canonicalization.

use thiserror::Error;

#[derive(Debug, Error)]
#[error(
    "invalid username: must be 3-32 characters, lowercase letters, numbers, and underscores only"
)]
pub struct UsernameError;

/// Canonicalize a username: trim whitespace and lowercase.
pub fn canonicalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

/// Validate a username.
///
/// - Length: 3–32 characters
/// - Characters: lowercase letters, digits, underscores only (`[a-z0-9_]`)
pub fn validate_username(username: &str) -> Result<(), UsernameError> {
    let len = username.len();
    if !(3..=32).contains(&len) {
        return Err(UsernameError);
    }
    for c in username.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_') {
            return Err(UsernameError);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "username_tests.rs"]
mod tests;
