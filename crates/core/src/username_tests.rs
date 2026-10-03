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
