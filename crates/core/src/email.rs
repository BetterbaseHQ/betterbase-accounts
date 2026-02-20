//! Email validation and canonicalization.
//!
//! Rules match the Go server's `services/email.go` exactly.

use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid email format")]
pub struct EmailError;

/// Gmail and Googlemail domains receive special canonicalization.
fn is_gmail_domain(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("gmail.com") || domain.eq_ignore_ascii_case("googlemail.com")
}

/// Validate an email address.
///
/// Requirements (matching Go server):
/// - ASCII only
/// - Max 254 characters total
/// - Must contain exactly one `@`
/// - Local part and domain must both be non-empty
pub fn validate_email(email: &str) -> Result<(), EmailError> {
    if email.is_empty() || email.len() > 254 {
        return Err(EmailError);
    }
    // ASCII only
    if !email.is_ascii() {
        return Err(EmailError);
    }
    // Must have exactly one @
    let at_count = email.bytes().filter(|&b| b == b'@').count();
    if at_count != 1 {
        return Err(EmailError);
    }
    let (local, domain) = email.split_once('@').unwrap();
    if local.is_empty() || domain.is_empty() {
        return Err(EmailError);
    }
    // Domain must have at least one dot
    if !domain.contains('.') {
        return Err(EmailError);
    }
    Ok(())
}

/// Canonicalize an email address.
///
/// - Domain is always lowercased.
/// - For Gmail/Googlemail: local part is lowercased; dots are removed; `+tag` suffix is stripped.
/// - All other domains: local part is preserved as-is (case-sensitive per RFC 5321).
pub fn canonicalize_email(email: &str) -> String {
    let (local, domain) = email
        .split_once('@')
        .expect("canonicalize_email called with invalid email");
    let domain_lower = domain.to_ascii_lowercase();

    let canonical_local = if is_gmail_domain(&domain_lower) {
        // Strip +alias suffix
        let local_no_tag = local.split('+').next().unwrap_or(local);
        // Lowercase and remove dots
        local_no_tag
            .to_ascii_lowercase()
            .chars()
            .filter(|&c| c != '.')
            .collect()
    } else {
        local.to_string()
    };

    format!("{}@{}", canonical_local, domain_lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_emails() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user+tag@gmail.com").is_ok());
        assert!(validate_email("a@b.co").is_ok());
    }

    #[test]
    fn invalid_emails() {
        assert!(validate_email("").is_err());
        assert!(validate_email("nodomain").is_err());
        assert!(validate_email("@nodomain.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("user@nodot").is_err());
        // Non-ASCII
        assert!(validate_email("user@éxample.com").is_err());
    }

    #[test]
    fn gmail_canonicalization() {
        assert_eq!(
            canonicalize_email("User.Name+tag@gmail.com"),
            "username@gmail.com"
        );
        assert_eq!(canonicalize_email("USER@GMAIL.COM"), "user@gmail.com");
        assert_eq!(
            canonicalize_email("u.s.e.r@googlemail.com"),
            "user@googlemail.com"
        );
    }

    #[test]
    fn non_gmail_canonicalization() {
        // Only domain is lowercased; local part preserved
        assert_eq!(canonicalize_email("User@Example.COM"), "User@example.com");
        // Dots and + are preserved for non-Gmail
        assert_eq!(
            canonicalize_email("user.name+tag@example.com"),
            "user.name+tag@example.com"
        );
    }
}
