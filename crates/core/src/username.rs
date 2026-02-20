//! Username validation and canonicalization.
//!
//! Rules match the Go server's `services/username.go` exactly.

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
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(validate_username("abc").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("a".repeat(32).as_str()).is_ok());
    }

    #[test]
    fn invalid_usernames() {
        assert!(validate_username("ab").is_err()); // too short
        assert!(validate_username(&"a".repeat(33)).is_err()); // too long
        assert!(validate_username("User").is_err()); // uppercase
        assert!(validate_username("user-name").is_err()); // hyphen
        assert!(validate_username("user name").is_err()); // space
        assert!(validate_username("").is_err());
    }

    #[test]
    fn canonicalize() {
        assert_eq!(canonicalize_username("  Alice  "), "alice");
        assert_eq!(canonicalize_username("BOB"), "bob");
    }
}
