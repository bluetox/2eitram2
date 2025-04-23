use super::utils;
use rand::rngs::OsRng;
use tauri::{AppHandle, Emitter};

pub async fn handle_ct(buffer: &Vec<u8>) -> Result<(), String> {
    let dilithium_signature = &buffer[5..5 + 3293];
    let ed25519_signature = &buffer[5 + 3293..5 + 3293 + 64];

    let dilihium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let ct = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64..];

    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);

    let full_hash_input = [
        &dilihium_pub_key[..],
        &ed25519_public_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    if pqc_dilithium::verify(&dilithium_signature, &data_to_sign_bytes, &dilihium_pub_key).is_err() {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &ed25519_public_key);
    if public_key.verify(&data_to_sign_bytes, &ed25519_signature).is_err() {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let source_user_id = utils::create_user_id_hash(&full_hash_input);

    {
        let chat_id =  crate::database::utils::chat_id_from_data(&source_user_id, &dst_id_hex).await.unwrap();

        let kyber_keys =  crate::database::utils::get_chat_kyber_keys(&chat_id).await.unwrap();
        let ss = safe_pqc_kyber::decapsulate(ct, &kyber_keys.secret)
            .map_err(|e| format!("Kyber decapsulation failed: {:?}", e))?;

        let mut locked_client = super::super::TCP_CLIENT.lock().await;
        locked_client.set_shared_secret(&source_user_id, &ss.to_vec()).await;
        
        crate::database::utils::save_shared_secret(source_user_id.clone().as_ref(), &dst_id_hex, ss.to_vec())
            .await
            .map_err(|e| format!("Failed to save shared secret: {:?}", e))?;
    }

    Ok(())
}

pub async fn handle_kyber(buffer: &Vec<u8>) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;

    let dilithium_signature = &buffer[5..5 + 3293];
    let ed25519_signature = &buffer[5 + 3293..5 + 3293 + 64];

    let dilithium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let kyber_public_key =
        &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64..];

    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);

    let full_hash_input = [&dilithium_pub_key[..], &ed25519_public_key[..], &src_id_nonce[..]].concat();

    if pqc_dilithium::verify(&dilithium_signature, &data_to_sign_bytes, &dilithium_pub_key).is_err() {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key =  ring::signature::UnparsedPublicKey::new(& ring::signature::ED25519, &ed25519_public_key);
    if public_key.verify(&data_to_sign_bytes, &ed25519_signature).is_err() {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let (ciphertext, shared_secret) = match safe_pqc_kyber::encapsulate(&kyber_public_key, &mut rng) {
        Ok(result) => result,
        Err(_) => return Err("Kyber encapsulation failed".to_string()),
    };

    let user_id = utils::create_user_id_hash(&full_hash_input);

    let mut locked_client = super::super::TCP_CLIENT.lock().await;
    locked_client.set_shared_secret(&user_id, &shared_secret.to_vec()).await;
    drop(locked_client);
    if crate::database::utils::save_shared_secret(&user_id.clone(), &dst_id_hex ,shared_secret.to_vec())
        .await
        .is_err()
    {
        return Err("Failed to save shared secret".to_string());
    }

    let source_id_bytes = match hex::decode(user_id) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Failed to decode dst_id_hex".to_string()),
    };
    
    let response = crate::network::utils::send_cyphertext(source_id_bytes, ciphertext.to_vec()).await;

    Ok(response)
}

pub async fn handle_message(buffer: &Vec<u8>, app: &AppHandle) -> Result<(), String> {
    let dilithium_signature = &buffer[5 .. 5 + 3293];
    let ed25519_signature = &buffer[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_pub_key = &buffer[5 + 3293 + 64.. 5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);
    let data_to_sign_bytes = &buffer[5 + 3293 + 64 ..];

    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    if !pqc_dilithium::verify(&dilithium_signature, &data_to_sign_bytes, &dilithium_pub_key).is_ok() {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &ed25519_pub_key);
    if let Err(_) = public_key.verify(&data_to_sign_bytes, &ed25519_signature) {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let source_id = utils::create_user_id_hash(&full_hash_input);

    let locked_client = super::super::TCP_CLIENT.lock().await;
    let ss = locked_client
        .get_shared_secret(&source_id)
        .await
        .map_err(|e| {
            println!("Failed to get shared_secret: {}", e);
            e
    })?;
    drop(locked_client);
    match crate::encryption::utils::decrypt_message(
        &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..].to_vec(),
        &ss,
    )
    .await
    {
        Ok(decrypted_message) => {
            crate::database::utils::save_received_message(&source_id, &dst_id_hex, &decrypted_message).await?;
            app.emit(
                "received-message",
                format!(
                    "{{\"source\": \"{}\", \"message\": \"{}\"}}",
                    source_id, decrypted_message
                ),
            ).map_err(|_| "Failed to emit received message to webview")?;
            Ok(())
        }
        Err(e) => {
            println!("[ERROR] Decryption failed: {:?}", e);
            Err(format!("Decryption failed: {:?}", e))
        }
    }
}
