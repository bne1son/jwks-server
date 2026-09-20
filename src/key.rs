use rand::thread_rng;
use rsa::{
    RsaPrivateKey,
    RsaPublicKey,
    traits::PublicKeyParts,
    pkcs1v15::SigningKey,
    signature::{
        RandomizedSigner,
        SignatureEncoding,
        Verifier
    },
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::Sha256;


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
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut rng = thread_rng();
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key.sign_with_rng(&mut rng, message);
        return signature.to_bytes().to_vec();
    }

    pub fn kid(&self) -> &str {&self.kid}
    pub fn modulus(&self) -> String {
        return URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be());
    }
    pub fn exponent(&self) -> String {
        return URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be());
    }
    pub fn is_expired(&self, now: u64) -> bool {
        if (now >= self.expires_at) {
            return true;
        }
        return false
    }

    pub fn expires_at(&self) -> u64 {
        return self.expires_at;
    }
}