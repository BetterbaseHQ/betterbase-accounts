#![forbid(unsafe_code)]
//! keygen — Generate a hex-encoded OPAQUE ServerSetup blob.
//!
//! Run once to generate the server setup secret. The output goes into the
//! `OPAQUE_SERVER_SETUP` environment variable.

fn main() {
    let hex = betterbase_accounts_auth::opaque::OpaqueService::generate_server_setup_hex();
    println!("{hex}");
}
