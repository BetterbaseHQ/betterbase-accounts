use super::*;
use proptest::prelude::*;
use serde_json::{json, Value};

fn public_key(scalar: u64) -> Value {
    // Every nonzero u64 is below the P-256 group order, avoiding discarded cases.
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&scalar.to_be_bytes());
    let key = p256::SecretKey::from_slice(&bytes).unwrap();
    let point = key.public_key().to_sec1_point(false);
    json!({ "kty": "EC", "crv": "P-256",
        "x": B64URL.encode(point.x().unwrap()), "y": B64URL.encode(point.y().unwrap()) })
}

fn json_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        ".{0,64}".prop_map(Value::String)
    ]
    .prop_recursive(3, 32, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(".{0,16}", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn generated_public_keys_normalize_without_changing_identity(
        scalar in 1u64..=u64::MAX, metadata in json_value(),
    ) {
        let key = public_key(scalar);
        let mut decorated = key.clone();
        decorated["kid"] = metadata.clone();
        decorated["extra"] = metadata;
        let normalized = validate_p256_public_key(&decorated).unwrap();
        prop_assert_eq!(&normalized, &key);
        prop_assert_eq!(validate_p256_public_key(&normalized).unwrap(), key.clone());
        prop_assert_eq!(jwk_thumbprint_b64(&decorated).unwrap(), jwk_thumbprint_b64(&key).unwrap());
    }

    #[test]
    fn any_private_key_field_is_rejected(scalar in 1u64..=u64::MAX, private in json_value()) {
        let mut key = public_key(scalar);
        prop_assert!(validate_p256_public_key(&key).is_ok());
        key["d"] = private;
        prop_assert!(validate_p256_public_key(&key).is_err());
    }

    #[test]
    fn wrong_coordinate_lengths_are_rejected(
        scalar in 1u64..=u64::MAX, coordinate in prop_oneof![Just("x"), Just("y")],
        bytes in prop::collection::vec(any::<u8>(), 0..65).prop_filter("not 32 bytes", |v| v.len() != 32),
    ) {
        let mut key = public_key(scalar);
        key[coordinate] = B64URL.encode(bytes).into();
        prop_assert!(validate_p256_public_key(&key).is_err());
    }

    #[test]
    fn arbitrary_jwk_shapes_do_not_panic(value in json_value()) {
        let _ = validate_p256_public_key(&value);
    }

    #[test]
    fn pkce_binds_verifier_and_recipient(
        verifier in "[A-Za-z0-9._~-]{43,128}", scalar in 1u64..=u64::MAX,
    ) {
        let thumbprint = jwk_thumbprint_b64(&public_key(scalar)).unwrap();
        let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        let bound = B64URL.encode(Sha256::digest(format!("{verifier}{thumbprint}").as_bytes()));
        let mut other_verifier = verifier.clone();
        other_verifier.replace_range(..1, if verifier.starts_with('A') { "B" } else { "A" });
        let mut other_thumbprint = thumbprint.clone();
        other_thumbprint.replace_range(..1, if thumbprint.starts_with('A') { "B" } else { "A" });
        prop_assert!(verify_pkce(&verifier, &challenge));
        prop_assert!(!verify_pkce(&other_verifier, &challenge));
        prop_assert!(verify_pkce_with_thumbprint(&verifier, &thumbprint, &bound));
        prop_assert!(!verify_pkce_with_thumbprint(&other_verifier, &thumbprint, &bound));
        prop_assert!(!verify_pkce_with_thumbprint(&verifier, &other_thumbprint, &bound));
        prop_assert!(!verify_pkce_with_thumbprint(&verifier, &thumbprint, &challenge));
        prop_assert!(!verify_pkce(&verifier, &bound));
    }
}
