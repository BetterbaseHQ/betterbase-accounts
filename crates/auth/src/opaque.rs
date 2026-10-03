//! OPAQUE password authentication using `opaque-ke` v4 (Ristretto255 cipher suite).
//!
//! Registration records and protocol messages use the `opaque-ke` wire format.

use opaque_ke::{
    ksf::Identity, rand::rngs::OsRng, CipherSuite, CredentialFinalization, CredentialRequest,
    Identifiers, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup, TripleDh,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpaqueError {
    #[error("invalid OPAQUE request")]
    InvalidRequest,
    #[error("invalid OPAQUE record")]
    InvalidRecord,
    #[error("invalid credential request (KE1)")]
    InvalidKE1,
    #[error("invalid credential finalization (KE3)")]
    InvalidKE3,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("OPAQUE protocol error: {0}")]
    Protocol(String),
}

/// Cipher suite using Ristretto255 with Triple-DH and no server-side KSF.
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, sha2_legacy::Sha512>;
    type Ksf = Identity;
}

/// Server identity string embedded in OPAQUE key exchange.
const SERVER_ID: &[u8] = b"betterbase-accounts";

/// Result of a server registration start.
pub struct RegistrationStartResult {
    /// Serialized RegistrationResponse bytes to send to client.
    pub response: Vec<u8>,
}

/// Result of a server login start.
pub struct LoginStartResult {
    /// Serialized CredentialResponse (KE2) bytes to send to client.
    pub ke2: Vec<u8>,
    /// Serialized ServerLogin state to persist (60s TTL).
    pub server_state: Vec<u8>,
}

/// OPAQUE server-side protocol service.
///
/// `server_setup` is loaded from `OPAQUE_SERVER_SETUP` hex env var and stays constant.
pub struct OpaqueService {
    server_setup: ServerSetup<DefaultCipherSuite>,
}

impl OpaqueService {
    /// Create the service from a hex-encoded `ServerSetup`.
    pub fn from_hex(hex_str: &str) -> Result<Self, OpaqueError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| OpaqueError::Protocol("invalid hex in server setup".to_string()))?;
        let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&bytes)
            .map_err(|e| OpaqueError::Protocol(format!("invalid server setup: {e}")))?;
        Ok(Self { server_setup })
    }

    /// Start server-side OPAQUE registration.
    ///
    /// `credential_id` is the account UUID bytes used as the credential identifier.
    pub fn registration_start(
        &self,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<RegistrationStartResult, OpaqueError> {
        let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(request_bytes)
            .map_err(|_| OpaqueError::InvalidRequest)?;

        let result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.server_setup,
            request,
            credential_id,
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok(RegistrationStartResult {
            response: result.message.serialize().to_vec(),
        })
    }

    /// Finalize server-side OPAQUE registration.
    ///
    /// Returns the serialized registration record to store in the DB.
    pub fn registration_finish(&self, upload_bytes: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(upload_bytes)
            .map_err(|_| OpaqueError::InvalidRecord)?;

        let record = ServerRegistration::<DefaultCipherSuite>::finish(upload);
        Ok(record.serialize().to_vec())
    }

    /// Start server-side OPAQUE login.
    ///
    /// If `record_bytes` is `None`, a fake login response is generated
    /// (anti-enumeration).
    pub fn login_start(
        &self,
        ke1_bytes: &[u8],
        record_bytes: Option<&[u8]>,
        credential_id: &[u8],
    ) -> Result<LoginStartResult, OpaqueError> {
        let mut rng = OsRng;

        let password_file = record_bytes
            .map(|b| {
                ServerRegistration::<DefaultCipherSuite>::deserialize(b)
                    .map_err(|_| OpaqueError::InvalidRecord)
            })
            .transpose()?;

        let credential_request = CredentialRequest::<DefaultCipherSuite>::deserialize(ke1_bytes)
            .map_err(|_| OpaqueError::InvalidKE1)?;

        let result = ServerLogin::<DefaultCipherSuite>::start(
            &mut rng,
            &self.server_setup,
            password_file,
            credential_request,
            credential_id,
            ServerLoginParameters {
                identifiers: Identifiers {
                    server: Some(SERVER_ID),
                    client: None,
                },
                context: None,
            },
        )
        .map_err(|e| OpaqueError::Protocol(e.to_string()))?;

        Ok(LoginStartResult {
            ke2: result.message.serialize().to_vec(),
            server_state: result.state.serialize().to_vec(),
        })
    }

    /// Finish server-side OPAQUE login.
    ///
    /// Returns `Ok(())` on successful authentication.
    pub fn login_finish(
        &self,
        ke3_bytes: &[u8],
        server_state_bytes: &[u8],
    ) -> Result<(), OpaqueError> {
        let state = ServerLogin::<DefaultCipherSuite>::deserialize(server_state_bytes)
            .map_err(|_| OpaqueError::Protocol("invalid server state".to_string()))?;

        let ke3 = CredentialFinalization::<DefaultCipherSuite>::deserialize(ke3_bytes)
            .map_err(|_| OpaqueError::InvalidKE3)?;

        state
            .finish(
                ke3,
                ServerLoginParameters {
                    identifiers: Identifiers {
                        server: Some(SERVER_ID),
                        client: None,
                    },
                    context: None,
                },
            )
            .map_err(|_| OpaqueError::AuthenticationFailed)?;
        Ok(())
    }

    /// Generate a new `ServerSetup` and return it as hex.
    ///
    /// Used by the `keygen` binary.
    pub fn generate_server_setup_hex() -> String {
        let mut rng = OsRng;
        let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
        hex::encode(setup.serialize())
    }
}

#[cfg(feature = "test-support")]
#[path = "opaque_test_support.rs"]
mod test_support;

#[cfg(feature = "test-support")]
pub use test_support::{
    test_registration_start, test_registration_upload, TestLogin, TestRegistration,
};

#[cfg(test)]
#[path = "opaque_property_tests.rs"]
mod property_tests;

#[cfg(test)]
#[path = "opaque_tests.rs"]
mod tests;
