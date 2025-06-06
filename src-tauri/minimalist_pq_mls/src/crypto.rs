use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::{rngs::OsRng, RngCore};

pub fn derive_aes_key(shared_secret: &[u8]) -> Key<Aes256Gcm> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"aes-gcm key", &mut okm).expect("HKDF expand failed");
    Key::<Aes256Gcm>::from_slice(&okm).clone()
}

pub fn encrypt_with_aes(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("encryption failed");

    let mut output = ciphertext;
    output.extend_from_slice(&nonce_bytes);
    output
}

pub fn decrypt_with_aes(key: &Key<Aes256Gcm>, ciphertext_with_nonce: &[u8]) -> Vec<u8> {
    let len = ciphertext_with_nonce.len();
    assert!(len > 12, "ciphertext too short");

    let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_at(len - 12);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .expect("decryption failed")
}


pub fn derive_secret(secret: &Vec<u8>, label: &str) -> Vec<u8>{
    let info = [b"PQ-MLS 1.0 ", label.as_bytes()].concat();

    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).expect("HKDF expand failed");
    okm.to_vec()
}

pub fn key_exchange() -> Key<Aes256Gcm> {
    let mut rng = OsRng;
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);

    derive_aes_key(&secret)
}