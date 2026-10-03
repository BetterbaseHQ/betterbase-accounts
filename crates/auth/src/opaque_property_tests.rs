use super::*;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use proptest::prelude::*;
use std::sync::OnceLock;

fn service() -> &'static OpaqueService {
    static SERVICE: OnceLock<OpaqueService> = OnceLock::new();
    SERVICE.get_or_init(|| {
        OpaqueService::from_hex(&OpaqueService::generate_server_setup_hex()).unwrap()
    })
}

proptest! {
    #[test]
    fn generated_credentials_authenticate_but_altered_proofs_do_not(
        password in prop::collection::vec(any::<u8>(), 1..128),
        credential in any::<[u8; 16]>(),
        index in any::<usize>(), mask in 1u8..=255,
    ) {
        let svc = service();
        let mut rng = OsRng;
        let registration = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, &password).unwrap();
        let response = svc.registration_start(&registration.message.serialize(), &credential).unwrap();
        let upload = registration.state.finish(
            &mut rng, &password, RegistrationResponse::deserialize(&response.response).unwrap(),
            ClientRegistrationFinishParameters {
                identifiers: Identifiers { server: Some(SERVER_ID), client: None }, ksf: None,
            },
        ).unwrap();
        let record = svc.registration_finish(&upload.message.serialize()).unwrap();
        let login = ClientLogin::<DefaultCipherSuite>::start(&mut rng, &password).unwrap();
        let response = svc.login_start(&login.message.serialize(), Some(&record), &credential).unwrap();
        let finish = login.state.finish(
            &mut rng, &password, CredentialResponse::deserialize(&response.ke2).unwrap(),
            ClientLoginFinishParameters {
                identifiers: Identifiers { server: Some(SERVER_ID), client: None }, context: None, ksf: None,
            },
        ).unwrap();
        let mut proof = finish.message.serialize().to_vec();
        prop_assert!(svc.login_finish(&proof, &response.server_state).is_ok());
        let position = index % proof.len();
        proof[position] ^= mask;
        prop_assert!(svc.login_finish(&proof, &response.server_state).is_err());
    }

    #[test]
    fn arbitrary_wire_messages_and_setup_do_not_panic(
        message in prop::collection::vec(any::<u8>(), 0..512),
        state in prop::collection::vec(any::<u8>(), 0..512),
        credential in any::<[u8; 16]>(),
    ) {
        let svc = service();
        let _ = OpaqueService::from_hex(&hex::encode(&message));
        let _ = svc.registration_start(&message, &credential);
        let _ = svc.registration_finish(&message);
        let _ = svc.login_start(&message, None, &credential);
        let _ = svc.login_start(&message, Some(&state), &credential);
        let _ = svc.login_finish(&message, &state);
    }
}
