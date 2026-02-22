//! OPAQUE password authentication using `opaque-ke` v4 (Ristretto255 cipher suite).
//!
//! Matches the Go server's behavior while using a completely different (incompatible)
//! wire format. Existing Go-server registrations cannot be used here.

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
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    };

    /// Helper: run a full OPAQUE registration round-trip in-process.
    fn full_registration(
        service: &OpaqueService,
        password: &[u8],
        credential_id: &[u8],
    ) -> Vec<u8> {
        let mut rng = OsRng;

        // Client registration start
        let client_start =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let ke1_bytes = client_start.message.serialize().to_vec();

        // Server registration start
        let server_start = service
            .registration_start(&ke1_bytes, credential_id)
            .unwrap();

        // Client registration finish
        let server_response =
            RegistrationResponse::<DefaultCipherSuite>::deserialize(&server_start.response)
                .unwrap();
        // Use SERVER_ID so the envelope is sealed with the same identifiers used at login.
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password,
                server_response,
                ClientRegistrationFinishParameters {
                    identifiers: Identifiers {
                        server: Some(SERVER_ID),
                        client: None,
                    },
                    ksf: None,
                },
            )
            .unwrap();
        let upload_bytes = client_finish.message.serialize().to_vec();

        // Server registration finish
        service.registration_finish(&upload_bytes).unwrap()
    }

    #[test]
    fn registration_round_trip() {
        let hex = OpaqueService::generate_server_setup_hex();
        let service = OpaqueService::from_hex(&hex).unwrap();
        let record = full_registration(&service, b"hunter2", b"test-user-id");
        assert!(!record.is_empty());
    }

    #[test]
    fn login_round_trip() {
        let hex = OpaqueService::generate_server_setup_hex();
        let service = OpaqueService::from_hex(&hex).unwrap();
        let credential_id = b"test-user-id";
        let password = b"hunter2";

        let record = full_registration(&service, password, credential_id);

        let mut rng = OsRng;

        // Client login start
        let client_login_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let ke1_bytes = client_login_start.message.serialize().to_vec();

        // Server login start
        let server_result = service
            .login_start(&ke1_bytes, Some(&record), credential_id)
            .unwrap();

        // Client login finish
        let ke2 =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&server_result.ke2).unwrap();
        let client_finish = client_login_start
            .state
            .finish(
                &mut rng,
                password,
                ke2,
                ClientLoginFinishParameters {
                    identifiers: Identifiers {
                        server: Some(SERVER_ID),
                        client: None,
                    },
                    context: None,
                    ksf: None,
                },
            )
            .unwrap();
        let ke3_bytes = client_finish.message.serialize().to_vec();

        // Server login finish
        service
            .login_finish(&ke3_bytes, &server_result.server_state)
            .unwrap();
    }

    #[test]
    fn fake_login_does_not_panic() {
        let hex = OpaqueService::generate_server_setup_hex();
        let service = OpaqueService::from_hex(&hex).unwrap();
        let mut rng = OsRng;

        let client_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"pass").unwrap();
        let ke1_bytes = client_start.message.serialize().to_vec();

        // None = fake login
        let result = service.login_start(&ke1_bytes, None, b"nonexistent-user");
        assert!(result.is_ok());
    }
}
