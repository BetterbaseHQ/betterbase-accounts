#![forbid(unsafe_code)]

pub mod email;
pub mod identity;
pub mod protocol;
pub mod username;

/// Verification token purpose constants.
pub mod purpose {
    pub const REGISTRATION: &str = "registration";
    pub const RECOVERY: &str = "recovery";
}
