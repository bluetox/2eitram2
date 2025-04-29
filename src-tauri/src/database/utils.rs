use std::collections::HashMap;
use crate::GLOBAL_DB;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Profile {
    pub profile_id: String,
    pub profile_name: String,
}


#[derive(Debug, sqlx::FromRow)]
pub struct KyberKeys {
    pub perso_kyber_public: Vec<u8>,
    pub perso_kyber_secret: Vec<u8>,
}

pub async fn get_chat_kyber_keys(chat_id: &str) -> Result<safe_pqc_kyber::Keypair, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result = sqlx::query_as::<_, KyberKeys>(
        "SELECT perso_kyber_public, perso_kyber_secret FROM private_chats WHERE chat_id = ?"
    )
        .bind(chat_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to load shared secrets: {}", e))?;

    let mut k_public_key_array = [0u8; 1568];
    let mut k_private_key_array = [0u8; 3168];

    k_public_key_array.copy_from_slice(&result.perso_kyber_public);
    k_private_key_array.copy_from_slice(&result.perso_kyber_secret);

    let kyber_keys = safe_pqc_kyber::Keypair {
        public: k_public_key_array,
        secret: k_private_key_array
    };
    Ok(kyber_keys)
}

pub async fn _get_shared_secrets(shared_secrets: &mut HashMap<String, Vec<u8>>) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;

    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "
        SELECT private_chats.shared_secret, private_chats.dst_user_id
        FROM private_chats
        JOIN chats ON private_chats.chat_id = chats.chat_id
        WHERE chats.chat_profil = ? AND chats.chat_type = 'private'
        "
    )
    .bind(&current_profile)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to load shared secrets: {}", e))?;

    for (shared_secret, dst_user_id) in rows {
        if shared_secret.len() != 32 {
            if !shared_secret.is_empty() {
                println!("Warning: Shared secret for user_id {} is not 32 bytes. Skipping.", dst_user_id);
            }
            continue;
        }
        shared_secrets.insert(dst_user_id, shared_secret);
    }

    Ok(())
}


pub async fn save_shared_secret(source_id: &str, dst_id: &str, shared_secret: Vec<u8>) -> Result<String, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let profil_dst: String = sqlx::query_scalar("SELECT profile_name FROM profiles WHERE user_id = ?")
        .bind(dst_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    let chat_id: String = sqlx::query_scalar(
            r#"
            SELECT p.chat_id
              FROM private_chats AS p
              JOIN chats AS c
                ON p.chat_id = c.chat_id
             WHERE p.dst_user_id = ?1
               AND c.chat_profil  = ?2
            "#,
        )
        .bind(&source_id)
        .bind(&profil_dst)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

        sqlx::query(
            "UPDATE private_chats SET shared_secret = ?, send_root_secret = ?, recv_root_secret = ? WHERE chat_id = ?"
        )
            .bind(&shared_secret)
            .bind(&shared_secret)
            .bind(&shared_secret)
            .bind(&chat_id)   
            .execute(db)
            .await
            .map_err(|e| format!("Error updating shared secret: {}", e))?;

    Ok(chat_id)
}

pub async fn chat_id_from_data(
    source_id: &str,dst_id: &str
) -> Result<String, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let profil_dst: String = sqlx::query_scalar("SELECT profile_name FROM profiles WHERE user_id = ?")
        .bind(dst_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    let chat_id: String = sqlx::query_scalar(
            r#"
            SELECT p.chat_id
              FROM private_chats AS p
              JOIN chats AS c
                ON p.chat_id = c.chat_id
             WHERE p.dst_user_id = ?1
               AND c.chat_profil  = ?2
            "#,
        )
        .bind(&source_id)
        .bind(&profil_dst)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;
    Ok(chat_id)
}

pub async fn save_message(
    chat_id: &str, source_id: &str, message: &str, message_type: &str
) -> Result<(), String> {

    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");
    let key = &keys.global_key;

    let encrypted_message_vec = crate::encryption::utils::encrypt_message(&message, &key).await;
    let encrypted_message = hex::encode(encrypted_message_vec);

    let current_time = chrono::Utc::now().timestamp();

    sqlx::query("UPDATE chats SET last_updated = ? WHERE chat_id = ?")
        .bind(&current_time)
        .bind(&chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error updating shared secret: {}", e))?;

    let message_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO messages (message_id, sender_id, message_type, content, chat_id) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(message_id)
        .bind(source_id)
        .bind(message_type)
        .bind(encrypted_message)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving todo: {}", e))?;
    Ok(())
}

pub async fn get_secret(
    s_type: &str,
    chat_id: &str,
) -> Result<Vec<u8>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let column = match s_type {
        "send_root_secret" => "send_root_secret",
        "recv_root_secret" => "recv_root_secret",
        other => return Err(format!("Invalid secret type: {}", other)),
    };

    let sql = format!(
        "SELECT {} FROM private_chats WHERE chat_id = ?",
        column
    );

    let secret: Vec<u8> = sqlx::query_scalar(&sql)
        .bind(chat_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get {}: {}", column, e))?;

    Ok(secret)
}

pub async fn set_new_secret(
    s_type: &str,
    chat_id: &str,
    secret: Vec<u8>,
) -> Result<(), String> {
    let db = match GLOBAL_DB.get() {
        Some(db) => {
            db
        }
        None => {
            println!("[ERROR] Database not initialized");
            return Err("Database not initialized".to_string());
        }
    };

    let sql = match s_type {
        "send_root_secret" => {
            "UPDATE private_chats SET send_root_secret = ? WHERE chat_id = ?"
        }
        "recv_root_secret" => {
            "UPDATE private_chats SET recv_root_secret = ? WHERE chat_id = ?"
        }
        other => {
            let msg = format!("Invalid secret type: {}", other);
            println!("[ERROR] {}", msg);
            return Err(msg);
        }
    };

    let query = sqlx::query(sql)
        .bind(&secret)
        .bind(chat_id);
    
    let result = query.execute(db).await;
    match result {
        Ok(_) => {
            Ok(())
        }
        Err(e) => {
            let err_msg = format!("Error updating {}: {}", s_type, e);
            println!("[ERROR] {}", err_msg);
            Err(err_msg)
        }
    }
}

