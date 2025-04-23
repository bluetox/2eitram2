use bytes::BytesMut;
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};

/* 
pub async fn create_add_chat_packet(dst_id_hex: &str, groupe_name: &str, group_id: &str) -> Vec<u8> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().ok_or("Keys not initialized").unwrap();
    
    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();
    let kyber_public_key = keys.kyber_keys.public;

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e)).unwrap();
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let dst_id_bytes = hex::decode(dst_id_hex).unwrap();
    let mut group_name_bytes = groupe_name.as_bytes().to_vec();
    group_name_bytes.extend_from_slice(b"\n");

    let group_id_bytes = group_id.as_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len() + dst_id_bytes.len() + kyber_public_key.len()  + group_name_bytes.len() + group_id_bytes.len()
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);
    sign_part.extend_from_slice(&kyber_public_key);
    sign_part.extend_from_slice(&group_name_bytes);
    sign_part.extend_from_slice(&group_id_bytes);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0xb0, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let client = super::super::TCP_CLIENT.lock().await;
    let node_shared_secret = client.get_node_shared_secret().await;
    let encrypted_packet = super::super::modules::encryption::encrypt_packet(&raw_packet, &node_shared_secret).await;
    drop(client);
    encrypted_packet
}
*/
pub async fn create_get_nodes_packet() -> Vec<u8>{
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().ok_or("Keys not initialized").unwrap();
    
    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e)).unwrap();
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len()
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0x0a, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let total_size = raw_packet.len() as u16;
    raw_packet[1..3].copy_from_slice(&total_size.to_le_bytes());
    raw_packet.to_vec()
}


pub async fn create_server_connect_packet(ss : Vec<u8>) -> Result<Vec<u8>, String> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().ok_or("Keys not initialized")?;
    
    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e))?;
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len()
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    
    let encrypted_packet = crate::encryption::utils::encrypt_packet(&raw_packet, &ss).await;

    Ok(encrypted_packet)
}