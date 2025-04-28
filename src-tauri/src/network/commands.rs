#[tauri::command]
pub async fn establish_ss(dst_user_id: String, chat_id: String) -> Result<(), String> {
    {
        let kyber_keys = crate::database::utils::get_chat_kyber_keys(&chat_id).await?;
        let mut client = super::super::TCP_CLIENT.lock().await;
        client.send_kyber_key(hex::decode(dst_user_id).unwrap(), &kyber_keys).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn send_message(chat_id: String, dst_id_hexs: String, message_string: String) {
    {
        let mut client = super::super::TCP_CLIENT.lock().await;
        client.send_message(&chat_id, &dst_id_hexs, &message_string).await;
        crate::database::utils::save_message(
            &chat_id,
            &dst_id_hexs,
            &message_string,
            "sent"
        ).await.unwrap();

    }
}
