#[tauri::command]
pub async fn establish_ss(dst_user_id: String, chat_id: String) {
    {
        let kyber_keys = crate::database::utils::get_chat_kyber_keys(&chat_id).await.unwrap();
        let mut client = super::super::TCP_CLIENT.lock().await;
        client.send_kyber_key(hex::decode(dst_user_id).unwrap(), &kyber_keys).await;
    }
}

#[tauri::command]
pub async fn send_message(dst_id_hexs: String, message_string: String) {
    {
        let mut client = super::super::TCP_CLIENT.lock().await;
        client.send_message(dst_id_hexs, message_string).await;
    }
}
