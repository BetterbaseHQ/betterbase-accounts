use super::*;

/// Client-side OPAQUE registration start for integration tests
/// (`test-support` feature): returns the KE1 bytes that recover/init and
/// registration endpoints expect in `opaque_request`.
pub fn test_registration_start(password: &[u8]) -> Result<Vec<u8>, OpaqueError> {
    use opaque_ke::ClientRegistration;
    let mut rng = OsRng;
    let client_start = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password)
        .map_err(|_| OpaqueError::InvalidKE1)?;
    Ok(client_start.message.serialize().to_vec())
}

/// In-process OPAQUE client registration for integration tests
/// (`test-support` feature): runs a full client round against this
/// service and returns the registration upload bytes that the API's
/// finalize endpoints expect in `opaque_record`.
pub fn test_registration_upload(
    service: &OpaqueService,
    password: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
    let mut rng = OsRng;

    let client_start = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password)
        .map_err(|_| OpaqueError::InvalidKE1)?;
    let ke1_bytes = client_start.message.serialize().to_vec();
    let server_start = service.registration_start(&ke1_bytes, credential_id)?;
    let server_response =
        RegistrationResponse::<DefaultCipherSuite>::deserialize(&server_start.response)
            .map_err(|_| OpaqueError::InvalidRequest)?;
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
        .map_err(|_| OpaqueError::InvalidKE3)?;
    Ok(client_finish.message.serialize().to_vec())
}

/// Stateful OPAQUE client for route-level registration tests.
pub struct TestRegistration(opaque_ke::ClientRegistration<DefaultCipherSuite>);

impl TestRegistration {
    pub fn start(password: &[u8]) -> (Self, Vec<u8>) {
        let started =
            opaque_ke::ClientRegistration::start(&mut OsRng, password).expect("start registration");
        (Self(started.state), started.message.serialize().to_vec())
    }

    pub fn finish(self, password: &[u8], response: &[u8]) -> Vec<u8> {
        let response = opaque_ke::RegistrationResponse::deserialize(response)
            .expect("decode registration response");
        self.0
            .finish(
                &mut OsRng,
                password,
                response,
                opaque_ke::ClientRegistrationFinishParameters {
                    identifiers: Identifiers {
                        server: Some(SERVER_ID),
                        client: None,
                    },
                    ksf: None,
                },
            )
            .expect("finish registration")
            .message
            .serialize()
            .to_vec()
    }
}

/// Stateful OPAQUE client for route-level login and password-change tests.
pub struct TestLogin(opaque_ke::ClientLogin<DefaultCipherSuite>);

impl TestLogin {
    pub fn start(password: &[u8]) -> (Self, Vec<u8>) {
        let started = opaque_ke::ClientLogin::start(&mut OsRng, password).expect("start login");
        (Self(started.state), started.message.serialize().to_vec())
    }

    pub fn finish(self, password: &[u8], ke2: &[u8]) -> Vec<u8> {
        let response = opaque_ke::CredentialResponse::deserialize(ke2).expect("decode KE2");
        self.0
            .finish(
                &mut OsRng,
                password,
                response,
                opaque_ke::ClientLoginFinishParameters {
                    identifiers: Identifiers {
                        server: Some(SERVER_ID),
                        client: None,
                    },
                    context: None,
                    ksf: None,
                },
            )
            .expect("finish login")
            .message
            .serialize()
            .to_vec()
    }
}
