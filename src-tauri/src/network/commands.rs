use rand::rngs::OsRng;

#[tauri::command]
pub async fn establish_ss(dst_user_id: String, chat_id: String) -> Result<(), String> {
    let kyber_keys = crate::database::utils::get_chat_kyber_keys(&chat_id).await?;
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
pub async fn send_message(chat_id: String, dst_id_hexs: String, message_string: String) -> Result<(), String> {
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
                        
    if let Some(tcp_client) = tcp_guard.as_mut() {
        tcp_client.send_message(&chat_id, &dst_id_hexs, &message_string).await;
    } else {
        println!("No existing TCP client found");
    }
    drop(tcp_guard);

    crate::database::utils::save_message(
        &chat_id,
        &dst_id_hexs,
        &message_string,
        "sent"
    ).await.unwrap();
    if crate::database::commands::need_for_rekey(&chat_id).await? {
        let new_keypair = safe_pqc_kyber::Keypair::generate(&mut OsRng);
        crate::database::commands::new_chat_keypair(&new_keypair, &chat_id).await?;
        let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
                        
        if let Some(tcp_client) = tcp_guard.as_mut() {
            tcp_client.send_kyber_key(hex::decode(dst_id_hexs).unwrap(), &new_keypair).await;
        } else {
            println!("No existing TCP client found");
        }
    }
    Ok(())
}
