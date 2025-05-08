use rand::rngs::OsRng;
use tauri::Emitter;
use std::str;
use rand::RngCore;

pub async fn handle_ct(
    buffer: &Vec<u8>
) -> Result<(), String> {
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

    let source_user_id = crate::utils::create_user_id_hash(&full_hash_input);

    {
        let chat_id =  crate::database::private_chat::chat_id_from_data(&source_user_id, &dst_id_hex).await.unwrap();

        let kyber_keys =  crate::database::private_chat::get_chat_kyber_keys(&chat_id).await.unwrap();
        let ss = safe_pqc_kyber::decapsulate(ct, &kyber_keys.secret)
            .map_err(|e| format!("Kyber decapsulation failed: {:?}", e))?;

        crate::database::private_chat::save_shared_secret(source_user_id.clone().as_ref(), &dst_id_hex, ss.to_vec())
            .await
            .map_err(|e| format!("Failed to save shared secret: {:?}", e))?;
    }

    Ok(())
}

pub async fn handle_kyber(
    buffer: &Vec<u8>
) -> Result<(), String> {
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

    let (ciphertext, shared_secret) = match safe_pqc_kyber::encapsulate(&kyber_public_key, &mut rng, None) {
        Ok(result) => result,
        Err(_) => return Err("Kyber encapsulation failed".to_string()),
    };

    let user_id = crate::utils::create_user_id_hash(&full_hash_input);

    if crate::database::private_chat::save_shared_secret(&user_id, &dst_id_hex ,shared_secret.to_vec())
        .await
        .is_err()
    {
        crate::database::commands::create_private_chat("invite", &user_id).await.unwrap();
        crate::database::private_chat::save_shared_secret(&user_id, &dst_id_hex ,shared_secret.to_vec()).await.unwrap();
        let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
        let app = arc_app.lock().await;

        app.emit(
            "new-chat", {}).map_err(|_| "Failed to emit new chat to webview")?;
    }

    let source_id_bytes = match hex::decode(user_id) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Failed to decode dst_id_hex".to_string()),
    };
    
    crate::network::utils::send_cyphertext(source_id_bytes, ciphertext.to_vec()).await;

    Ok(())
}

pub async fn handle_message(
    buffer: &Vec<u8>
) -> Result<(), String> {
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

    let source_id = crate::utils::create_user_id_hash(&full_hash_input);

    let chat_id = crate::database::private_chat::chat_id_from_data(&source_id, &dst_id_hex).await.unwrap();
    let ss = crate::crypto::keys::ratchet_forward(&"recv_root_secret", &chat_id).await.unwrap();

    match crate::crypto::utils::decrypt_message(
        &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..].to_vec(),
        &ss.to_vec(),
    )
    .await
    {
        Ok(decrypted_message) => {

            crate::database::utils::save_message(&chat_id, &source_id, &decrypted_message, "received").await?;
            let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
            let app = arc_app.lock().await;
    
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


pub async fn handle_group_invite(
    buffer: &Vec<u8>
) {
    let source_id = crate::utils::source_id_from_packet(buffer);
    let group_id = str::from_utf8(&buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 ..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36]).unwrap();
    let group_name =  str::from_utf8(&buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36..]).unwrap();
    let public_key = crate::database::group_chat::save_new_group(group_id, group_name, &source_id).await.unwrap();
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;

    
    if let Some(tcp_client) = tcp_guard.as_mut() {
        let nss = tcp_client.get_node_shared_secret().await;
        let packet = super::packet::create_accept_invite_packet(group_id, &source_id, &nss, &public_key).await.unwrap();
        tcp_client.write(&packet).await;
    } else {
        println!("No existing TCP client found");
    } 

}

pub async fn handle_group_accept(
    buffer: &Vec<u8>
) {
    let group_id = str::from_utf8(&buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 ..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36]).unwrap();

    let kyber_key = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 ..];
    let dilithium_pub_key = &buffer[5 + 3293 + 64.. 5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    let new_member_uid = crate::utils::create_user_id_hash(&full_hash_input);

    let mut member_ps = [0u8; 32];
    OsRng.fill_bytes(&mut member_ps);

    let mut group = crate::database::group_chat::load_group_from_id(group_id).await.unwrap();

    let (new_member_index, _) = group.add_member(
        kyber_key.to_vec(), 
        dilithium_pub_key.to_vec(),
        ed25519_pub_key.to_vec(), 
        &new_member_uid, 
        member_ps.to_vec(), 
        None
    );

    println!("Inserted the new user at index: {}", new_member_index);

    crate::database::group_chat::save_group_state(group.clone(), group_id).await.unwrap();

    let hello_data = minimalist_pq_mls::packet::ClientHello {
        index: new_member_index,
        path_secret: member_ps.to_vec(),
        epoch: group.epoch,
        tree: group.tree.clone()
    };

    let hello_data_bytes = bincode::serialize(&hello_data).unwrap();

    super::packet::create_hello_packet(&hello_data_bytes, &new_member_uid, &kyber_key.to_vec(), &group_id).await.unwrap();

    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;    
    let tcp_client = tcp_guard.as_mut().unwrap();

    let keys = group.tree.get_keys_for_broadcast_new_member_secret(new_member_index);

    println!("Keys list for broadcast: {:?}", keys);

    let tree_height = keys.len() + 1;
    let mut new_pks = Vec::new();
    let index_path = group.tree.internal_path_indices(new_member_index);
    for index in index_path {
        new_pks.push((index, group.tree.nodes[index].as_ref().unwrap().public_key.clone()));
    }

    for i in 0..tree_height - 1 {
        let (members, node_index) = keys[i].clone();
        let mut new_secret = member_ps.to_vec();
        for _ in 0..i + 1{
            new_secret = minimalist_pq_mls::crypto::derive_secret(&new_secret, "node");
        }
        for mem_index in members {
            if group.self_index == mem_index  {
                continue;
            }
            match group.tree.members.get(mem_index) {
                Some(Some(member)) => {
                    let group_update = minimalist_pq_mls::GroupUpdateMember {
                        new_epoch: group.epoch,
                        key: new_secret.clone(),
                        index: new_member_index,
                        new_pks: new_pks.clone(),
                        new_member_cred: minimalist_pq_mls::Credential { 
                            kyber_pk: kyber_key.to_vec(), 
                            ed25519_pk: ed25519_pub_key.to_vec(),
                            dilithium_pk: dilithium_pub_key.to_vec(), 
                            user_id: new_member_uid.clone()
                        }
                    };

                    println!("Dest {} pk {}", &member.user_id, node_index);
                    let bin_update = bincode::serialize(&group_update).unwrap();

                    let (ct, secret) = safe_pqc_kyber::encapsulate(&group.tree.nodes[node_index].as_ref().unwrap().public_key, &mut OsRng, None).unwrap(); 
                    let encrypted_data = crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
                    let raw_packet = super::packet::create_group_update_packet(&member.user_id, &encrypted_data, &ct.to_vec(), &group_id).await.unwrap();
                    tcp_client.write_enc(&raw_packet).await;
                },
                Some(None) => {},
                None => {}
            }
        }
    }

    if new_member_index % 2 != 0 && new_member_index - 1 != group.self_index {
        let group_update = minimalist_pq_mls::GroupUpdateMember {
            new_epoch: group.epoch,
            key: member_ps.to_vec(),
            index: new_member_index,
            new_pks: new_pks,
            new_member_cred: minimalist_pq_mls::Credential { 
                kyber_pk: kyber_key.to_vec(), 
                ed25519_pk: ed25519_pub_key.to_vec(),
                dilithium_pk: dilithium_pub_key.to_vec(), 
                user_id: new_member_uid.clone()
            }
        };
        let member = group.tree.members[new_member_index - 1].as_ref().unwrap();
        println!("sent ps to {}", &member.user_id);
        let bin_update = bincode::serialize(&group_update).unwrap();
        let (ct, secret) = safe_pqc_kyber::encapsulate(&member.kyber_key, &mut OsRng, None).unwrap(); 
        let encrypted_data = crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
        let raw_packet = super::packet::create_group_update_packet(&member.user_id, &encrypted_data, &ct.to_vec(), &group_id).await.unwrap();
        tcp_client.write_enc(&raw_packet).await;
    }
}