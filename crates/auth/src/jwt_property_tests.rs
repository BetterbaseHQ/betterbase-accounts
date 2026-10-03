use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use proptest::prelude::*;
use std::sync::OnceLock;

fn service() -> &'static JwtService {
    static SERVICE: OnceLock<JwtService> = OnceLock::new();
    SERVICE.get_or_init(|| {
        let (private, public) = crate::es256::generate_keypair().unwrap();
        JwtService::new(
            1,
            vec![42; 32],
            1,
            private,
            vec![(1, public)],
            "https://accounts.test".into(),
        )
    })
}

fn access_token(subject: &str) -> String {
    let now = Utc::now();
    service()
        .create_oauth_access_token(OAuthAccessClaims {
            sub: subject.into(),
            iss: service().issuer.clone(),
            aud: vec!["client".into()],
            exp: (now + Duration::minutes(15)).timestamp(),
            iat: now.timestamp(),
            client_id: "client".into(),
            grant_id: "grant".into(),
            scope: "openid".into(),
            did: "did:key:test".into(),
            personal_space_id: "space".into(),
            mailbox_id: None,
        })
        .unwrap()
}

// Exercise every token family with the same malformed/tampered input.
fn all_reject(token: &str) -> bool {
    let svc = service();
    svc.validate_auth_token(token).is_err()
        && svc
            .validate_state_token(token, StatePurpose::Login)
            .is_err()
        && svc.validate_verification_token(token).is_err()
        && svc.validate_oauth_state_token(token).is_err()
        && svc.validate_oauth_access_token(token).is_err()
}

proptest! {
    #[test]
    fn subjects_and_credential_versions_survive_signing(subject in ".{0,128}", version in any::<i64>()) {
        let token = service().create_auth_token(&subject, version).unwrap();
        let claims = service().validate_auth_token(&token).unwrap();
        prop_assert_eq!(claims.sub, subject);
        prop_assert_eq!(claims.cred_ver, version);
    }

    #[test]
    fn changing_a_signed_subject_is_rejected(subject in ".{0,128}") {
        for token in [service().create_auth_token(&subject, 0).unwrap(), access_token(&subject)] {
            prop_assert!(!all_reject(&token));
            let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
            let mut payload: serde_json::Value = serde_json::from_slice(&B64URL.decode(&parts[1]).unwrap()).unwrap();
            payload["sub"] = format!("{subject}!").into();
            parts[1] = B64URL.encode(serde_json::to_vec(&payload).unwrap());
            prop_assert!(all_reject(&parts.join(".")));
        }
    }

    #[test]
    fn corrupted_signatures_are_rejected(index in any::<usize>(), mask in 1u8..=255) {
        let svc = service();
        let tokens = [
            svc.create_auth_token("subject", 0).unwrap(),
            svc.create_state_token("state", StatePurpose::Login, 0).unwrap(),
            svc.create_verification_token("user@example.test", "registration").unwrap(),
            svc.create_oauth_state_token(OAuthStateClaims::new(
                "client".into(), "https://app.test/cb".into(), "openid".into(),
                "state".into(), "challenge".into(), "S256".into(), None,
            )).unwrap(),
            access_token("subject"),
        ];
        for token in tokens {
            prop_assert!(!all_reject(&token));
            let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
            let mut signature = B64URL.decode(&parts[2]).unwrap();
            let position = index % signature.len();
            signature[position] ^= mask;
            parts[2] = B64URL.encode(signature);
            prop_assert!(all_reject(&parts.join(".")));
        }
    }

    #[test]
    fn state_purposes_cannot_be_substituted(subject in ".{0,128}", version in any::<i64>(), index in 0usize..5) {
        let purposes = [StatePurpose::Registration, StatePurpose::Login, StatePurpose::PasswordChangeLogin,
            StatePurpose::PasswordChange, StatePurpose::Recovery];
        let token = service().create_state_token(&subject, purposes[index], version).unwrap();
        for purpose in purposes {
            let result = service().validate_state_token(&token, purpose);
            prop_assert_eq!(result.is_ok(), purpose == purposes[index]);
            if let Ok(claims) = result {
                prop_assert_eq!(&claims.sub, &subject);
                prop_assert_eq!(claims.cred_ver, version);
            }
        }
    }

    #[test]
    fn arbitrary_token_text_does_not_panic(token in ".{0,2048}") {
        // No acceptance assertion: this property tests parser robustness. The
        // signed-token properties above test authentication, using valid controls.
        let svc = service();
        let _ = svc.validate_auth_token(&token);
        let _ = svc.validate_state_token(&token, StatePurpose::Login);
        let _ = svc.validate_verification_token(&token);
        let _ = svc.validate_oauth_state_token(&token);
        let _ = svc.validate_oauth_access_token(&token);
    }
}
