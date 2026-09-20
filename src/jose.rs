use serde::Serialize;
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use crate::key::Key;


#[derive(Serialize)]
pub struct Jwk {
    kty: String,    // key type
    kid: String,    // key ID
    #[serde(rename = "use")]
    use_: String,   // use (signature)
    alg: String,    // algorithm
    n: String,      // modulus
    e: String,      // exponent
}

impl Jwk {
    // create a jwk based off the RSA key
    pub fn from_key(key: &Key) -> Self {
        Self {
            kty: "RSA".to_string(),
            kid: key.kid().to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            n: key.modulus(),
            e: key.exponent(),
        }
    }
}

#[derive(Serialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    // create a jwk set
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self {keys}
    }
}

#[derive(Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

pub fn jwt_create_header(key: &Key) -> String {
    // create jwt header using RSA key's id
    let header = JwtHeader {
        alg: "RS256".to_string(),
        typ: "JWT".to_string(),
        kid: key.kid().to_string(),
    };
    // json-ify the header
    return serde_json::to_string(&header).unwrap();
}

#[derive(Serialize)]
struct JwtPayload {
    // only claim is exponent
    exp: u64,
}

pub fn jwt_create_payload(key: &Key) -> String {
    let payload = JwtPayload {
        exp: key.expires_at(),
    };
    // json-ify the payload
    serde_json::to_string(&payload).unwrap()
}

pub fn to_base64(input: &str) -> String {
    return URL_SAFE_NO_PAD.encode(input);
}

pub fn base64url_bytes(input: &[u8]) -> String {
    return URL_SAFE_NO_PAD.encode(input);
}


// tests for jose related stuff
#[test]
fn jwk_contains_key_information() {
    let key = Key::new("test-key".to_string(), 100);
    let jwk = Jwk::from_key(&key);
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.kid, "test-key");
    assert_eq!(jwk.use_, "sig");
    assert_eq!(jwk.alg, "RS256");
    assert_eq!(jwk.n, key.modulus());
    assert_eq!(jwk.e, key.exponent());
}

#[test]
fn jwt_contains_required_fields() {
    let key = Key::new("test-key".to_string(), 100);
    let header = jwt_create_header(&key);
    assert!(header.contains("\"alg\":\"RS256\""));
    assert!(header.contains("\"typ\":\"JWT\""));
    assert!(header.contains("\"kid\":\"test-key\""));
    let key = Key::new("test-key".to_string(), 100);
    let payload = jwt_create_payload(&key);
    assert!(payload.contains("\"exp\":100"));
}

#[test]
fn base64url_encodes() {
    let encoded = to_base64("hello");
    assert_eq!(encoded, "aGVsbG8");
    let encoded = base64url_bytes(b"hello");
    assert_eq!(encoded, "aGVsbG8");
}

#[test]
fn jwks_contains_jwk() {
    let key = Key::new("test-key".to_string(), 100);
    let jwk = Jwk::from_key(&key);
    let jwks = Jwks::new(vec![jwk]);
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid, "test-key");
}

#[test]
fn jwt_signature_verifies() {
    let key = Key::new("test-key".to_string(), 100);
    let encoded_header = to_base64(
        &jwt_create_header(&key)
    );
    let encoded_payload = to_base64(
        &jwt_create_payload(&key)
    );
    let message = format!(
        "{}.{}",
        encoded_header,
        encoded_payload
    );
    let signature = key.sign(message.as_bytes());
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier,
    };
    use sha2::Sha256;
    let verifying_key = VerifyingKey::<Sha256>::new(key.public_key.clone());
    let signature = Signature::try_from(signature.as_slice()).unwrap();
    assert!(verifying_key
        .verify(message.as_bytes(), &signature)
        .is_ok());
}

#[test]
fn jwks_serializes_to_json() {
    let key = Key::new("test-key".to_string(), 100);
    let jwk = Jwk::from_key(&key);
    let jwks = Jwks::new(vec![jwk]);
    let json = serde_json::to_string(&jwks).unwrap();
    assert!(json.starts_with("{\"keys\":["));
    assert!(json.contains("\"kid\":\"test-key\""));
}