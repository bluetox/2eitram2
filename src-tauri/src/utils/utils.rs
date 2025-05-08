use sha2::{Digest, Sha256};

pub fn create_user_id_hash(
    input: &[u8]
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub async fn get_profile_name(
) -> String {
    super::super::PROFILE_NAME.lock().await.clone()
}

pub fn source_id_from_packet(
    packet: &Vec<u8>
) -> String {
    let dilithium_pub_key = &packet[5 + 3293 + 64.. 5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &packet[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &packet[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],
        &src_id_nonce[..],
    ]
    .concat();
    crate::utils::create_user_id_hash(&full_hash_input)
}