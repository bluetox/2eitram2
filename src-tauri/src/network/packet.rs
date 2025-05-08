use bytes::BytesMut;
use rand::rngs::OsRng;
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn create_get_nodes_packet(
) -> Vec<u8>{
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    
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


pub async fn create_server_connect_packet(
    ss : Vec<u8>
) -> Result<Vec<u8>, String> {
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    
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

    
    let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, &ss).await;

    Ok(encrypted_packet)
}

pub async fn create_send_message_packet(
    dst_id_hexs: &str, message_string: &str, ss: &Vec<u8>, nss: &Vec<u8>
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");


    let dst_id_bytes = hex::decode(&dst_id_hexs)?;

    let message = crate::crypto::utils::encrypt_message(&message_string, ss).await;

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
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

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0x04, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, nss).await;
    Ok(encrypted_packet)
}

pub async fn create_hello_packet(
    hello_data: &Vec<u8>, dst_id: &str, pk: &Vec<u8>, group_id: &str
) -> Result<(), String> {
    println!("{:?}", &pk[..5]);
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dst_id_bytes = hex::decode(&dst_id).unwrap();
    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap()
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    let (ct, new_secret) = safe_pqc_kyber::encapsulate(pk, &mut OsRng, None).unwrap();
    let group_id_bytes = group_id.as_bytes();

    let hello_data_enc = crate::crypto::utils::encrypt_data(hello_data, &new_secret.to_vec()).await;

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + group_id_bytes.len()
            + ct.len()
            + hello_data_enc.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&group_id_bytes);
    sign_part.extend_from_slice(&ct);
    sign_part.extend_from_slice(&hello_data_enc);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0xC2, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;                   
    let tcp_client = tcp_guard.as_mut().unwrap();
    let nss = tcp_client.get_node_shared_secret().await;

    let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, &nss).await;
    tcp_client.write(&encrypted_packet).await;

    drop(keys_lock);
    Ok(())
}

pub async fn create_accept_invite_packet(
    group_id: &str, dst_id: &str, nss: &Vec<u8>, kyber_pk: &Vec<u8>
) -> Result<Vec<u8>, String>{

    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");


    let dst_id_bytes = hex::decode(&dst_id).map_err(|_| "Invalid user_id_hex")?;
    let group_id_bytes = group_id.as_bytes();

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH).map_err(|_| "Time error")?
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + group_id_bytes.len()
            + kyber_pk.len()
    );

    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&group_id_bytes);
    sign_part.extend_from_slice(&kyber_pk);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0xC1, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, nss).await;

    Ok(encrypted_packet)
}

pub async fn create_group_invite_packet(
    user_id: &str, group_id: Vec<u8>, group_name: Vec<u8>, nss: &Vec<u8>
) -> Result<Vec<u8>, String> {
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let user_id_bytes = hex::decode(user_id).unwrap();
    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e))?;
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + user_id_bytes.len() + keys.nonce.len() + timestamp.len() + group_id.len() + group_name.len()
    );

    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&user_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);
    sign_part.extend_from_slice(&group_id);
    sign_part.extend_from_slice(&group_name);


    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);
    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0xC0, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, &nss).await;
    Ok(encrypted_packet)
}

pub async fn create_send_group_message_packet(
    dst_id_hexs: &str, message_string: &str, group_id: &str, root_key: &Vec<u8>
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dst_id_bytes = hex::decode(&dst_id_hexs)?;
    let group_id_bytes = group_id.as_bytes();

    let message = crate::crypto::utils::encrypt_message(&message_string, root_key).await;

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + group_id_bytes.len()
            + message.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&group_id_bytes);
    sign_part.extend_from_slice(&message);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0xC7, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    Ok(raw_packet.to_vec())
}

pub async fn create_group_update_packet(
    dst_id: &str, enc_group_data: &Vec<u8>, ct: &Vec<u8>, group_id: &str
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dst_id_bytes = hex::decode(&dst_id)?;
    let group_id_bytes = group_id.as_bytes();


    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + group_id_bytes.len()
            + ct.len()
            + enc_group_data.len()
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&group_id_bytes);
    sign_part.extend_from_slice(&ct);
    sign_part.extend_from_slice(&enc_group_data);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    raw_packet.extend_from_slice(&[0xC5, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    Ok(raw_packet.to_vec())
}