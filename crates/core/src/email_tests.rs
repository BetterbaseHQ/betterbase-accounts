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
