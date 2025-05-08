use rand::rngs::OsRng;

#[tauri::command]
pub async fn establish_ss(
    chat_id: String
) -> Result<(), String> {
    let kyber_keys = crate::database::private_chat::get_chat_kyber_keys(&chat_id).await?;
    let dst_user_id = crate::database::private_chat::get_dst_id_from_chat_id(&chat_id).await?;
    {
        let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
                        
        if let Some(tcp_client) = tcp_guard.as_mut() {
            tcp_client.send_kyber_key(hex::decode(dst_user_id).unwrap(), &kyber_keys).await;
        } else {
            println!("No existing TCP client found");
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn send_message(
    chat_id: String, message_string: String
) -> Result<(), String> {
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
    let dst_user_id = crate::database::private_chat::get_dst_id_from_chat_id(&chat_id).await?;
    if let Some(tcp_client) = tcp_guard.as_mut() {
        tcp_client.send_message(&chat_id, &dst_user_id, &message_string).await;
    } else {
        println!("No existing TCP client found");
    }
    drop(tcp_guard);

    crate::database::utils::save_message(
        &chat_id,
        &dst_user_id,
        &message_string,
        "sent"
    ).await.unwrap();
    if crate::database::private_chat::need_for_rekey(&chat_id).await? {
        let new_keypair = safe_pqc_kyber::keypair(&mut OsRng, None);
        crate::database::private_chat::new_chat_keypair(&new_keypair, &chat_id).await?;
        let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
                        
        if let Some(tcp_client) = tcp_guard.as_mut() {
            tcp_client.send_kyber_key(hex::decode(dst_user_id).unwrap(), &new_keypair).await;
        } else {
            println!("No existing TCP client found");
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn send_group_message(chat_id: &str, message: &str) -> Result<(), String> {
    let group = crate::database::group_chat::group_from_chat_id(chat_id).await.unwrap();
    let group_id = &group.group_id;
    let root = &group.get_root();
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
    let tcp = tcp_guard.as_mut().unwrap();

    
    for maybe_member in &group.tree.members {
        if let Some(member) = maybe_member {
            let raw_packet = super::packet::create_send_group_message_packet(&member.user_id, message, &group_id, &root[..32].to_vec()).await.unwrap();
            tcp.write_enc(&raw_packet).await;
        }
    }
    drop(tcp_guard);
    Ok(())
}