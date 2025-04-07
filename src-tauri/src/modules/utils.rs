use sha2::{Digest, Sha256};
use bytes::BytesMut;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::signature::KeyPair;

pub fn create_user_id_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub async fn get_profile_name() -> String {
    super::super::PROFILE_NAME.lock().await.clone()
}

pub async fn create_send_message_packet(
    dst_id_hexs: String,
    message_string: String,
) -> Vec<u8> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dst_id_bytes = hex::decode(&dst_id_hexs).unwrap();

    let shared_secret = {
        let shared_secret_locked = super::super::SHARED_SECRETS.lock().await;
        shared_secret_locked.get(&dst_id_hexs).expect("Shared secret not found").clone()
    };

    let message = super::encryption::encrypt_message(&message_string, &shared_secret).await;

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + message.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&message);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock );

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0x04, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let client = super::super::CLIENT.lock().await;
    let node_shared_secret = client.get_node_shared_secret().await;
    let encrypted_packet = super::encryption::encrypt_packet(&raw_packet, &node_shared_secret).await;
    drop(client);

    encrypted_packet
}