use super::objects::KyberKeys;
use crate::GLOBAL_DB;

use sqlx::Row;

// Get destination id given a chat id
pub async fn get_dst_id_from_chat_id(chat_id: &str) -> Result<String, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let row = sqlx::query(
        r#"
        SELECT dst_user_id FROM private_chats
        WHERE chat_id = ?1
        "#,
    )
    .bind(chat_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error while fetching chat: {}", e))?;

    if let Some(row) = row {
        let dst_id: String = row
            .try_get("dst_user_id")
            .map_err(|e| format!("Failed to extract dst_id: {}", e))?;
        Ok(dst_id)
    } else {
        Err("Direct chat not found for this profile".to_string())
    }
}

// Return the kyber keypair associated with the private chat
pub async fn get_chat_kyber_keys(chat_id: &str) -> Result<safe_pqc_kyber::Keypair, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result = sqlx::query_as::<_, KyberKeys>(
        "SELECT perso_kyber_public, perso_kyber_secret FROM private_chats WHERE chat_id = ?",
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
        secret: k_private_key_array,
    };
    Ok(kyber_keys)
}

// Given a source id and dst id as well as current profile returns the associated chat id
pub async fn chat_id_from_data(source_id: &str, dst_id: &str) -> Result<String, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let profil_dst = crate::PROFILE_NAME.lock().await.clone();

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

// Save shared secret for private chat
pub async fn save_shared_secret(
    source_id: &str,
    dst_id: &str,
    shared_secret: Vec<u8>,
) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let chat_id: String = chat_id_from_data(source_id, dst_id).await?;
    println!("saving shared secret for {:?}", chat_id);
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

    Ok(())
}

// Get a secret for private chat
pub async fn get_secret(s_type: &str, chat_id: &str) -> Result<Vec<u8>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let column = match s_type {
        "send_root_secret" => "send_root_secret",
        "recv_root_secret" => "recv_root_secret",
        other => return Err(format!("Invalid secret type: {}", other)),
    };

    let sql = format!("SELECT {} FROM private_chats WHERE chat_id = ?", column);

    let secret: Vec<u8> = sqlx::query_scalar(&sql)
        .bind(chat_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get {}: {}", column, e))?;

    Ok(secret)
}

// Save new secret for a private chat
pub async fn set_new_secret(s_type: &str, chat_id: &str, secret: Vec<u8>) -> Result<(), String> {
    let db = match GLOBAL_DB.get() {
        Some(db) => db,
        None => {
            println!("[ERROR] Database not initialized");
            return Err("Database not initialized".to_string());
        }
    };

    let sql = match s_type {
        "send_root_secret" => "UPDATE private_chats SET send_root_secret = ? WHERE chat_id = ?",
        "recv_root_secret" => "UPDATE private_chats SET recv_root_secret = ? WHERE chat_id = ?",
        other => {
            let msg = format!("Invalid secret type: {}", other);
            println!("[ERROR] {}", msg);
            return Err(msg);
        }
    };

    let query = sqlx::query(sql).bind(&secret).bind(chat_id);

    let result = query.execute(db).await;
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let err_msg = format!("Error updating {}: {}", s_type, e);
            println!("[ERROR] {}", err_msg);
            Err(err_msg)
        }
    }
}

pub async fn new_chat_keypair(
    keypair: &safe_pqc_kyber::Keypair,
    chat_id: &str,
) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    sqlx::query(
        "UPDATE private_chats SET perso_kyber_public = ?, perso_kyber_secret = ? WHERE chat_id = ?",
    )
    .bind(keypair.public.to_vec())
    .bind(keypair.secret.to_vec())
    .bind(chat_id)
    .execute(db)
    .await
    .map_err(|e| format!("Error upserting chat keypair: {}", e))?;

    Ok(())
}

// Verifies if the chat needs to initiate a rekey (done every 4 messages sent)
pub async fn need_for_rekey(chat_id: &str) -> Result<bool, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result: Option<(i64,)> =
        sqlx::query_as("SELECT COUNT(*) FROM messages WHERE chat_id = ? AND message_type = 'sent'")
            .bind(chat_id)
            .fetch_optional(db)
            .await
            .map_err(|e| format!("Failed to count messages: {}", e))?;

    Ok(matches!(result, Some((n,)) if n != 0 && n % 4 == 0))
}
