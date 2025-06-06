use rand::rngs::OsRng;
use tauri::Emitter;

pub async fn handle_ct(buffer: &Vec<u8>) -> Result<(), String> {
    let dilithium_signature = &buffer[5..5 + 3293];
    let ed25519_signature = &buffer[5 + 3293..5 + 3293 + 64];

    let dilihium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let ct = &buffer
        [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64..];

    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);

    let full_hash_input = [
        &dilihium_pub_key[..],
        &ed25519_public_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    if pqc_dilithium::verify(&dilithium_signature, &data_to_sign_bytes, &dilihium_pub_key).is_err()
    {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &ed25519_public_key);
    if public_key
        .verify(&data_to_sign_bytes, &ed25519_signature)
        .is_err()
    {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let source_user_id = crate::utils::create_user_id_hash(&full_hash_input);

    {
        let chat_id =
            crate::database::private_chat::chat_id_from_data(&source_user_id, &dst_id_hex)
                .await
                .unwrap();

        let kyber_keys = crate::database::private_chat::get_chat_kyber_keys(&chat_id)
            .await
            .unwrap();
        let ss = safe_pqc_kyber::decapsulate(ct, &kyber_keys.secret)
            .map_err(|e| format!("Kyber decapsulation failed: {:?}", e))?;

        crate::database::private_chat::save_shared_secret(
            source_user_id.clone().as_ref(),
            &dst_id_hex,
            ss.to_vec(),
        )
        .await
        .map_err(|e| format!("Failed to save shared secret: {:?}", e))?;
    }

    Ok(())
}

pub async fn handle_kyber(buffer: &Vec<u8>) -> Result<(), String> {
    let mut rng = OsRng;

    let dilithium_signature = &buffer[5..5 + 3293];
    let ed25519_signature = &buffer[5 + 3293..5 + 3293 + 64];

    let dilithium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let kyber_public_key = &buffer
        [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64..];

    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);

    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_public_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    if pqc_dilithium::verify(
        &dilithium_signature,
        &data_to_sign_bytes,
        &dilithium_pub_key,
    )
    .is_err()
    {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &ed25519_public_key);
    if public_key
        .verify(&data_to_sign_bytes, &ed25519_signature)
        .is_err()
    {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let (ciphertext, shared_secret) =
        match safe_pqc_kyber::encapsulate(&kyber_public_key, &mut rng, None) {
            Ok(result) => result,
            Err(_) => return Err("Kyber encapsulation failed".to_string()),
        };

    let user_id = crate::utils::create_user_id_hash(&full_hash_input);
    println!(
        "received ss from user: {} and dst is thought to be: {}",
        user_id, dst_id_hex
    );
    if crate::database::private_chat::save_shared_secret(
        &user_id,
        &dst_id_hex,
        shared_secret.to_vec(),
    )
    .await
    .is_err()
    {
        crate::database::commands::create_private_chat("invite", &user_id)
            .await
            .unwrap();
        crate::database::private_chat::save_shared_secret(
            &user_id,
            &dst_id_hex,
            shared_secret.to_vec(),
        )
        .await
        .unwrap();

        let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
        let app = arc_app.lock().await;
        
        app.emit("received-invite", &user_id)
            .map_err(|_| "Failed to emit new chat to webview").unwrap();
        println!("emitted");
    }

    let source_id_bytes = match hex::decode(user_id) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Failed to decode dst_id_hex".to_string()),
    };

    crate::network::utils::send_cyphertext(source_id_bytes, ciphertext.to_vec()).await;

    Ok(())
}

pub async fn handle_message(buffer: &Vec<u8>) -> Result<(), String> {
    let dilithium_signature = &buffer[5..5 + 3293];
    let ed25519_signature = &buffer[5 + 3293..5 + 3293 + 64];

    let dilithium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let dst_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32..5 + 3293 + 64 + 1952 + 32 + 32];
    let dst_id_hex = hex::encode(dst_id_bytes);
    let data_to_sign_bytes = &buffer[5 + 3293 + 64..];

    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    if !pqc_dilithium::verify(
        &dilithium_signature,
        &data_to_sign_bytes,
        &dilithium_pub_key,
    )
    .is_ok()
    {
        println!("[ERROR] Invalid Dilithium signature, dropping message.");
        return Err("Invalid Dilithium signature".to_string());
    }

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &ed25519_pub_key);
    if let Err(_) = public_key.verify(&data_to_sign_bytes, &ed25519_signature) {
        println!("[ERROR] Invalid Ed25519 signature, dropping message.");
        return Err("Invalid Ed25519 signature".to_string());
    }

    let source_id = crate::utils::create_user_id_hash(&full_hash_input);

    let chat_id = crate::database::private_chat::chat_id_from_data(&source_id, &dst_id_hex)
        .await
        .unwrap();
    let ss = crate::crypto::keys::ratchet_forward(&"recv_root_secret", &chat_id)
        .await
        .unwrap();

    match crate::crypto::utils::decrypt_message(
        &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..].to_vec(),
        &ss.to_vec(),
    )
    .await
    {
        Ok(decrypted_message) => {
            crate::database::utils::save_message(
                &chat_id,
                &source_id,
                &decrypted_message,
                "received",
            )
            .await?;
            let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
            let app = arc_app.lock().await;

            app.emit(
                "received-message",
                format!(
                    "{{\"source\": \"{}\", \"message\": \"{}\", \"chatId\": \"{}\"}}",
                    source_id, decrypted_message, chat_id
                ),
            )
            .map_err(|_| "Failed to emit received message to webview")?;
            Ok(())
        }
        Err(e) => {
            println!("[ERROR] Decryption failed: {:?}", e);
            Err(format!("Decryption failed: {:?}", e))
        }
    }
}
