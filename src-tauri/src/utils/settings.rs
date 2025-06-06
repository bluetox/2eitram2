use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ParamStore {
    theme: String,
    language: String,
    proxy: String,
    bubble_color: String,
    delete_delay: u32,

}


#[derive(Serialize, Deserialize)]
pub struct PrivateChatSettings {
    pub bubble_color: String,
    pub background_picture: Vec<u8>,
    pub packground_color: String,
    pub deletion_timer: u16, // minutes
    pub profile_picture: Vec<u8>,
    pub nickname: String,
}

impl Default for PrivateChatSettings {
    fn default() -> Self {
        Self {
            bubble_color: "#FFFFFF".to_string(),
            background_picture: Vec::new(),
            packground_color: "#000000".to_string(),
            deletion_timer: 0,
            profile_picture: Vec::new(),
            nickname: "Anonymous".to_string(),
        }
    }
}

#[tauri::command]
pub async fn get_params(chat_id: String) -> Result<PrivateChatSettings, String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let row: (Vec<u8>,) = sqlx::query_as(
        r#"SELECT settings FROM private_chats WHERE chat_id = ?1"#,
    )
    .bind(&chat_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("DB error: {}", e))?;

    let settings: PrivateChatSettings = bincode::deserialize(&row.0).unwrap();

    Ok(settings)
}
