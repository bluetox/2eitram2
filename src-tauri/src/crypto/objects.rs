use ring::signature::KeyPair;

pub struct Keys {
    pub dilithium_keys: DilithiumKeypair,
    pub ed25519_keys: Ed25519KeyPair,
    pub global_key: Vec<u8>,
    pub nonce: [u8; 16],
}

impl Keys {
    pub fn calculate_user_id(&self) -> String {
        let full_hash_input = [
            &self.dilithium_keys.public[..],
            &self.ed25519_keys.public_key().as_ref()[..],
            &self.nonce[..],
        ]
        .concat();
        crate::utils::create_user_id_hash(&full_hash_input)
    }
}

pub type DilithiumKeypair = pqc_dilithium::Keypair;
pub type KyberKeypair = safe_pqc_kyber::Keypair;
pub type Ed25519KeyPair = ring::signature::Ed25519KeyPair;
