//! Authentication context shared with API handlers.
//! Token validation lives in the API's `extract_auth` and `extract_oauth_token`.

use uuid::Uuid;

/// The authenticated account, after token and credential-version validation.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub account_id: Uuid,
}
