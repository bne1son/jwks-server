use rand::thread_rng;
use rsa::{
    RsaPrivateKey,
    RsaPublicKey,
    traits::PublicKeyParts
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};

pub struct Key {
    kid: String,
    expires_at: u64,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl Key {
    pub fn new(kid: String, expires_at: u64) -> Self {
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            kid,
            expires_at,
            private_key,
            public_key,
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }
    pub fn modulus(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be())
    }
    pub fn exponent(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be())
    }
}