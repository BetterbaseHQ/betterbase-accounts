use super::*;

#[test]
fn generate_and_encode() {
    let (priv_der, pub_der) = generate_keypair().unwrap();
    assert!(!priv_der.is_empty());
    assert!(!pub_der.is_empty());
}

#[test]
fn jwk_from_spki_der() {
    let (_, pub_der) = generate_keypair().unwrap();
    let jwk = Jwk::from_spki_der(1, &pub_der).unwrap();
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert!(!jwk.x.is_empty());
    assert!(!jwk.y.is_empty());
}

#[test]
fn jwks_from_keys() {
    let (_, pub_der) = generate_keypair().unwrap();
    let jwks = Jwks::from_signing_keys(&[(1, pub_der)]).unwrap();
    assert_eq!(jwks.keys.len(), 1);
}

#[test]
fn thumbprint_is_deterministic() {
    let (_, pub_der) = generate_keypair().unwrap();
    let jwk_val = Jwk::from_spki_der(1, &pub_der).unwrap().to_json_value();
    let tp1 = jwk_thumbprint(&jwk_val).unwrap();
    let tp2 = jwk_thumbprint(&jwk_val).unwrap();
    assert_eq!(tp1, tp2);
    assert!(!tp1.is_empty());
}
