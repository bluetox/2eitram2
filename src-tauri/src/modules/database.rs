use bip39::Mnemonic;
use futures::TryStreamExt;
use zeroize::Zeroize;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use std::collections::HashMap;
use super::{
    objects, 
    encryption, 
    utils,
    super::{
        GLOBAL_DB,
        PROFILE_NAME,
        ENCRYPTION_KEY
    }
};

#[tauri::command]
pub async fn create_profil(name: &str, mut password: String, mut phrase: String) -> Result<(), String> {

    let rng = SystemRandom::new();
    let mut kyber_rng = rand::rngs::OsRng;

    let mnemonic = Mnemonic::parse_normalized(&phrase).map_err(|_| "Invalid recovery phrase")?;

    let mut seed = mnemonic.to_seed("");

    phrase.zeroize();

    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "Failed to generate Ed25519 key pair".to_string())?;  

    let ed25519_keys: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| "Failed to parse Ed25519 key pair".to_string())?;

    let dilithium_keys = pqc_dilithium::Keypair::generate(&seed[..32]);

    seed.zeroize();

    let mut nonce = [0u8; 16];
    SecureRandom::fill(&rng, &mut nonce)
        .map_err(|_| "Failed to generate random bytes".to_string())?;

    let kyber_keys = pqc_kyber::keypair(&mut kyber_rng).map_err(|_| "Failed to generate kyber keypair")?;

    let full_hash_input = [
        &dilithium_keys.public[..],
        &ed25519_keys.public_key().as_ref()[..],
        &nonce[..],
    ]
    .concat();
    let user_id = utils::create_user_id_hash(&full_hash_input);

    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let hashed_password = bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

    let mut key = super::handle_keys::generate_pbkdf2_key(&password)?;
    password.zeroize();
    sqlx::query(
        "INSERT INTO profiles 
         (dilithium_public, dilithium_private, kyber_public, kyber_private, ed25519, nonce, user_id, password_hash, profile_name) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(encryption::encrypt_data(&dilithium_keys.public, &key).await)
        .bind(encryption::encrypt_data(dilithium_keys.expose_secret(), &key).await)
        .bind(encryption::encrypt_data(&kyber_keys.public, &key).await)
        .bind(encryption::encrypt_data(&kyber_keys.secret, &key).await)
        .bind(encryption::encrypt_data(pkcs8_bytes.as_ref(), &key).await)
        .bind(encryption::encrypt_data(&nonce, &key).await)
        .bind(user_id)
        .bind(hashed_password)
        .bind(name)
        .execute(db)
        .await
        .map_err(|e| format!("Error inserting profile: {}", e))?;
    key.zeroize();
    Ok(())
}

#[tauri::command]
pub async fn set_profile_name(name: String) {
    {
        let mut profile_name = PROFILE_NAME.lock().await;
        *profile_name = name;
    }
}
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Profile {
    pub profile_id: String,
    pub profile_name: String,
}

#[tauri::command]
pub async fn get_profiles() -> Result<Vec<Profile>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let chats: Vec<Profile> = sqlx::query_as::<_, Profile>("SELECT  profile_id, profile_name FROM profiles")
        .fetch_all(db)
        .await
        .map_err(|e| format!("Failed to get profiles: {}", e))?;

    Ok(chats)
}


#[tauri::command]
pub async fn delete_chat(chat_id: &str) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    
    sqlx::query("DELETE FROM chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&*db)
        .await
        .map_err(|e| format!("Error deleting chat: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub async fn add_chat(
    state: tauri::State<'_, objects::AppState>,
    name: &str,
    dst_user_id: &str,
) -> Result<String, String> {
    let db = &state.db;
    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_profile = utils::get_profile_name().await;
    let current_time = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO chats (chat_id, chat_name, dst_user_id, last_updated, chat_profil) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(name)
        .bind(dst_user_id)
        .bind(current_time)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    println!("Saved chat {} for user {} successfully", name, dst_user_id);

    Ok(chat_id)
}

#[tauri::command]
pub async fn has_shared_secret(chat_id: &str) -> Result<Option<bool>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT COUNT(*), shared_secret FROM chats WHERE chat_id = ?")
            .bind(chat_id)
            .fetch_optional(db)
            .await
            .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    match result {
        Some((0, _)) => Ok(None),
        Some((_, None)) => Ok(Some(false)),
        Some((_, Some(_))) => Ok(Some(true)),
        None => Ok(None),
    }
}

pub async fn get_shared_secrets(shared_secrets: &mut HashMap<String, Vec<u8>>) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let current_profile = utils::get_profile_name().await;
    let rows: Vec<(Vec<u8>, String)> =
        sqlx::query_as("SELECT shared_secret, dst_user_id FROM chats WHERE chat_profil = ?")
            .bind(&current_profile)
            .fetch_all(db)
            .await
            .map_err(|e| format!("Failed to load shared secrets: {}", e))?;


    for (shared_secret, dst_user_id) in rows {
        if shared_secret.len() != 32 {
            println!("Warning: Shared secret for user_id {} is not 32 bytes. Skipping.", dst_user_id);
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

    let chat_id: String = sqlx::query_scalar("SELECT chat_id FROM chats WHERE dst_user_id = ?1 AND chat_profil= ?2")
        .bind(&source_id)
        .bind(&profil_dst)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    sqlx::query("UPDATE chats SET shared_secret = ? WHERE chat_id = ?")
        .bind(&shared_secret)
        .bind(&chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error updating shared secret: {}", e))?;

    println!("Successfully saved shared secret for chat_id: {}", chat_id);

    Ok(chat_id)
}

#[tauri::command]
pub async fn save_message(
    state: tauri::State<'_, objects::AppState>,
    chat_id: &str,
    sender_id: &str,
    message: String,
) -> Result<(), String> {
    let db = &state.db;
    let key = ENCRYPTION_KEY.lock().await;
    
    let encrypted_message_vec = encryption::encrypt_message(&message, &key).await;
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
        .bind(sender_id)
        .bind("sent")
        .bind(encrypted_message)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving todo: {}", e))?;
    Ok(())
}

pub async fn save_received_message(
    source_id: &str,
    dst_id: &str,
    message: &str,
) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let key = ENCRYPTION_KEY.lock().await;
    let encrypted_message_vec = encryption::encrypt_message(&message, &key).await;
    let encrypted_message = hex::encode(encrypted_message_vec);

    let current_time = chrono::Utc::now().timestamp();

    let profil_dst: String = sqlx::query_scalar("SELECT profile_name FROM profiles WHERE user_id = ?")
        .bind(dst_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    let chat_id: String = sqlx::query_scalar("SELECT chat_id FROM chats WHERE dst_user_id = ?1 AND chat_profil= ?2")
        .bind(&source_id)
        .bind(&profil_dst)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

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
        .bind("received")
        .bind(encrypted_message)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving todo: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn get_messages(
    state: tauri::State<'_, objects::AppState>,
    chat_id: &str,
) -> Result<Vec<objects::Message>, String> {
    let db = &state.db;
    
    let key = ENCRYPTION_KEY.lock().await;
    
    let messages: Vec<objects::Message> =
        sqlx::query_as::<_, objects::Message>("SELECT * FROM messages WHERE chat_id = ?1")
            .bind(chat_id)
            .fetch(db)
            .try_collect()
            .await
            .map_err(|e| format!("Failed to get messages: {}", e))?;

        let mut decrypted_messages = Vec::new();
        for mut msg in messages {
            let encrypted_buffer = hex::decode(msg.content).map_err(|_| "Failed to parse encrypted message content as hex")?;
    
            match encryption::decrypt_message(&encrypted_buffer, &key).await {
                Ok(decrypted) => {
                    msg.content = decrypted;
                    decrypted_messages.push(msg);
                }
                Err(_) => return Err("Decryption failed".into()),
            }
        }
    Ok(decrypted_messages)
}

#[tauri::command]
pub async fn get_chats(state: tauri::State<'_, objects::AppState>) -> Result<Vec<objects::Chat>, String> {
    let db = &state.db;
    let current_profile = utils::get_profile_name().await;
    let chats: Vec<objects::Chat> = sqlx::query_as::<_, objects::Chat>("SELECT * FROM chats WHERE chat_profil = ?1 ORDER BY last_updated DESC")
        .bind(current_profile)
        .fetch(db)
        .try_collect()
        .await
        .map_err(|e| format!("Failed to get chats: {}", e))?;

    Ok(chats)
}
