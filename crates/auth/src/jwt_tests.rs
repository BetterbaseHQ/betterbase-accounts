use super::*;

fn test_service() -> JwtService {
    // Use the es256 module to generate test keys
    let (private_der, public_der) = crate::es256::generate_keypair().unwrap();
    JwtService::new(
        1,
        vec![0u8; 32],
        1,
        private_der.clone(),
        vec![(1, public_der)],
        "https://accounts.example.com".to_string(),
    )
}

#[test]
fn auth_token_roundtrip() {
    let svc = test_service();
    let token = svc.create_auth_token("user-uuid", 0).unwrap();
    let claims = svc.validate_auth_token(&token).unwrap();
    assert_eq!(claims.sub, "user-uuid");
}

#[test]
fn state_token_roundtrip() {
    let svc = test_service();
    let token = svc
        .create_state_token("state-uuid", StatePurpose::Login, 7)
        .unwrap();
    let id = svc
        .validate_state_token(&token, StatePurpose::Login)
        .unwrap();
    assert_eq!(id.sub, "state-uuid");
    assert_eq!(id.cred_ver, 7);
}

#[test]
fn state_tokens_are_bound_to_their_flow() {
    let svc = test_service();
    let purposes = [
        StatePurpose::Registration,
        StatePurpose::Login,
        StatePurpose::PasswordChangeLogin,
        StatePurpose::PasswordChange,
        StatePurpose::Recovery,
    ];
    for issued_for in purposes {
        let token = svc.create_state_token("state", issued_for, 0).unwrap();
        for accepted_for in purposes {
            assert_eq!(
                svc.validate_state_token(&token, accepted_for).is_ok(),
                issued_for == accepted_for,
                "{issued_for:?} token used for {accepted_for:?}",
            );
        }
    }
}

#[test]
fn legacy_state_without_flow_binding_is_rejected() {
    let svc = test_service();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("1".to_owned());
    let token = encode(
        &header,
        &serde_json::json!({
            "sub": "state",
            "typ": TYP_STATE,
            "iat": Utc::now().timestamp(),
            "exp": (Utc::now() + Duration::seconds(60)).timestamp(),
        }),
        &EncodingKey::from_secret(&svc.hmac_key),
    )
    .unwrap();
    assert!(svc
        .validate_state_token(&token, StatePurpose::Recovery)
        .is_err());
}

#[test]
fn verification_token_roundtrip() {
    let svc = test_service();
    let token = svc
        .create_verification_token("user@example.com", "registration")
        .unwrap();
    let claims = svc.validate_verification_token(&token).unwrap();
    assert_eq!(claims.email, "user@example.com");
    assert_eq!(claims.purpose, "registration");
    assert!(!claims.jti.is_empty());
}

#[test]
fn token_type_confusion_rejected() {
    let svc = test_service();

    let auth_token = svc.create_auth_token("user-uuid", 0).unwrap();
    let state_token = svc
        .create_state_token("state-uuid", StatePurpose::Login, 7)
        .unwrap();
    let verif_token = svc
        .create_verification_token("a@b.com", "registration")
        .unwrap();
    let oauth_state_token = svc
        .create_oauth_state_token(OAuthStateClaims::new(
            "cid".into(),
            "https://example.com/cb".into(),
            "openid".into(),
            "rand-state".into(),
            "challenge".into(),
            "S256".into(),
            None,
        ))
        .unwrap();

    // Each token type must be rejected by every other validator.
    // auth → others
    assert!(matches!(
        svc.validate_state_token(&auth_token, StatePurpose::Login),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_verification_token(&auth_token),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_oauth_state_token(&auth_token),
        Err(JwtError::InvalidToken)
    ));

    // state → others
    assert!(matches!(
        svc.validate_auth_token(&state_token),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_verification_token(&state_token),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_oauth_state_token(&state_token),
        Err(JwtError::InvalidToken)
    ));

    // verification → others
    assert!(matches!(
        svc.validate_auth_token(&verif_token),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_state_token(&verif_token, StatePurpose::Login),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_oauth_state_token(&verif_token),
        Err(JwtError::InvalidToken)
    ));

    // oauth-state → others
    assert!(matches!(
        svc.validate_auth_token(&oauth_state_token),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_state_token(&oauth_state_token, StatePurpose::Login),
        Err(JwtError::InvalidToken)
    ));
    assert!(matches!(
        svc.validate_verification_token(&oauth_state_token),
        Err(JwtError::InvalidToken)
    ));
}

#[test]
fn oauth_access_token_roundtrip() {
    let svc = test_service();
    let now = Utc::now();
    let claims = OAuthAccessClaims {
        sub: "user-uuid".to_string(),
        iss: svc.issuer.clone(),
        aud: vec!["client-uuid".to_string()],
        exp: (now + Duration::minutes(15)).timestamp(),
        iat: now.timestamp(),
        client_id: "client-uuid".to_string(),
        grant_id: "grant-uuid".to_string(),
        scope: "openid profile".to_string(),
        did: "did:key:zABC".to_string(),
        personal_space_id: "space-uuid".to_string(),
        mailbox_id: None,
    };
    let token = svc.create_oauth_access_token(claims.clone()).unwrap();
    let decoded = svc.validate_oauth_access_token(&token).unwrap();
    assert_eq!(decoded.sub, "user-uuid");
    assert_eq!(decoded.scope, "openid profile");
}
// Include every HS256 claim shape so cross-type rejection cannot pass
// merely because a required field happens to be missing.
fn complete_claims(typ: &str) -> serde_json::Value {
    serde_json::json!({
        "sub": "user", "typ": typ, "cred_ver": 7,
        "purpose": "login", "email": "alice@example.test", "jti": "unique-id",
        "client_id": "client", "redirect_uri": "https://app.test/cb",
        "scope": "openid", "state": "state", "code_challenge": "challenge",
        "code_challenge_method": "S256",
        "iat": Utc::now().timestamp(),
        "exp": (Utc::now() + Duration::minutes(15)).timestamp(),
    })
}

fn validate_internal(svc: &JwtService, typ: &str, token: &str) -> Result<(), JwtError> {
    match typ {
        TYP_AUTH => svc.validate_auth_token(token).map(|_| ()),
        TYP_STATE => svc
            .validate_state_token(token, StatePurpose::Login)
            .map(|_| ()),
        TYP_OAUTH_STATE => svc.validate_oauth_state_token(token).map(|_| ()),
        TYP_VERIFICATION => svc.validate_verification_token(token).map(|_| ()),
        _ => unreachable!(),
    }
}

#[test]
fn internal_validators_enforce_type_even_with_all_required_claims() {
    let svc = test_service();
    let types = [TYP_AUTH, TYP_STATE, TYP_OAUTH_STATE, TYP_VERIFICATION];
    for issued in types {
        let token = encode(
            &Header::new(Algorithm::HS256),
            &complete_claims(issued),
            &EncodingKey::from_secret(&svc.hmac_key),
        )
        .unwrap();
        for accepted in types {
            assert_eq!(
                validate_internal(&svc, accepted, &token).is_ok(),
                issued == accepted,
                "{issued} used as {accepted}"
            );
        }
    }
}

#[test]
fn internal_validators_reject_expiry_wrong_keys_algorithms_and_missing_claims() {
    let svc = test_service();
    for typ in [TYP_AUTH, TYP_STATE, TYP_OAUTH_STATE, TYP_VERIFICATION] {
        for defect in [
            "expired",
            "signature",
            "algorithm",
            "unknown-kid",
            "missing-exp",
            "missing-type",
        ] {
            let mut claims = complete_claims(typ);
            let mut header = Header::new(Algorithm::HS256);
            let mut secret = svc.hmac_key.clone();
            match defect {
                // Beyond the validator's default clock-skew allowance.
                "expired" => claims["exp"] = (Utc::now() - Duration::minutes(5)).timestamp().into(),
                "signature" => secret = vec![99; 32],
                "algorithm" => header.alg = Algorithm::HS384,
                "unknown-kid" => header.kid = Some("999".into()),
                "missing-exp" => {
                    claims.as_object_mut().unwrap().remove("exp");
                }
                "missing-type" => {
                    claims.as_object_mut().unwrap().remove("typ");
                }
                _ => unreachable!(),
            }
            let token = encode(&header, &claims, &EncodingKey::from_secret(&secret)).unwrap();
            let result = validate_internal(&svc, typ, &token);
            assert!(result.is_err(), "{typ} accepted {defect}");
            if defect == "expired" {
                assert!(matches!(result, Err(JwtError::TokenExpired)));
            }
        }
        for malformed in ["", "not-a-jwt", "a.b.c", "e30.e30."] {
            assert!(validate_internal(&svc, typ, malformed).is_err());
        }
    }
}

#[test]
fn access_tokens_reject_expiry_unknown_keys_and_forged_signatures() {
    let svc = test_service();
    let claims = serde_json::json!({
        "sub": "user", "iss": svc.issuer, "aud": ["client"],
        "exp": (Utc::now() + Duration::minutes(15)).timestamp(),
        "iat": Utc::now().timestamp(), "client_id": "client", "grant_id": "grant",
        "scope": "openid", "did": "did:key:zABC", "personal_space_id": "space",
    });
    let (other_private, _) = crate::es256::generate_keypair().unwrap();
    for defect in [
        "none",
        "expired",
        "issuer",
        "unknown-kid",
        "signature",
        "algorithm",
    ] {
        let mut claims = claims.clone();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("1".into());
        let mut key = EncodingKey::from_ec_der(&svc.es256_private_der);
        match defect {
            "expired" => claims["exp"] = (Utc::now() - Duration::minutes(5)).timestamp().into(),
            "issuer" => claims["iss"] = "https://foreign.example.test".into(),
            "unknown-kid" => header.kid = Some("999".into()),
            "signature" => key = EncodingKey::from_ec_der(&other_private),
            "algorithm" => {
                header.alg = Algorithm::HS256;
                key = EncodingKey::from_secret(&svc.hmac_key);
            }
            _ => {}
        }
        let token = encode(&header, &claims, &key).unwrap();
        assert_eq!(
            svc.validate_oauth_access_token(&token).is_ok(),
            defect == "none",
            "{defect}"
        );
    }
}
