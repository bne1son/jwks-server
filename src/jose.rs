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
    use_: String,   // use (encryption)
    alg: String,    // algorithm
    n: String,      // modulus
    e: String,      // exponent
}

impl Jwk {
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
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

#[derive(Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

pub fn jwt_create_header(key: &Key) -> String {
    let header = JwtHeader {
        alg: "RS256".to_string(),
        typ: "JWT".to_string(),
        kid: key.kid().to_string(),
    };
    return serde_json::to_string(&header).unwrap();
}

#[derive(Serialize)]
struct JwtPayload {
    exp: u64,
}

pub fn jwt_create_payload(key: &Key) -> String {
    let payload = JwtPayload {
        exp: key.expires_at(),
    };
    serde_json::to_string(&payload).unwrap()
}

pub fn to_base64(input: &str) -> String {
    return URL_SAFE_NO_PAD.encode(input);
}

pub fn base64url_bytes(input: &[u8]) -> String {
    return URL_SAFE_NO_PAD.encode(input);
}