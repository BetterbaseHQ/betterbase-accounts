use super::*;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};

/// Helper: run a full OPAQUE registration round-trip in-process.
fn full_registration(service: &OpaqueService, password: &[u8], credential_id: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;

    // Client registration start
    let client_start = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let ke1_bytes = client_start.message.serialize().to_vec();

    // Server registration start
    let server_start = service
        .registration_start(&ke1_bytes, credential_id)
        .unwrap();

    // Client registration finish
    let server_response =
        RegistrationResponse::<DefaultCipherSuite>::deserialize(&server_start.response).unwrap();
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
    let client_login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let ke1_bytes = client_login_start.message.serialize().to_vec();

    // Server login start
    let server_result = service
        .login_start(&ke1_bytes, Some(&record), credential_id)
        .unwrap();

    // Client login finish
    let ke2 = CredentialResponse::<DefaultCipherSuite>::deserialize(&server_result.ke2).unwrap();
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
