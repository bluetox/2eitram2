use super::objects::{ChatInfo, Message, Profile};
use crate::{crypto, utils, GLOBAL_DB, PROFILE_NAME};

use bip39::Mnemonic;
use futures::TryStreamExt;
use rand::{rngs::OsRng, RngCore};
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroize;

// Gets all the profiles from the database will name and user id
#[tauri::command]
pub async fn get_profiles() -> Result<Vec<Profile>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let profiles: Vec<Profile> =
        sqlx::query_as::<_, Profile>("SELECT  profile_id, profile_name FROM profiles")
            .fetch_all(db)
            .await
            .map_err(|e| format!("Failed to get profiles: {}", e))?;

    Ok(profiles)
}

// Delete a chat from database given a chat id
#[tauri::command]
pub async fn delete_chat(chat_id: &str) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let mut tx = db
        .begin()
        .await
        .map_err(|e| format!("Transaction start failed: {}", e))?;

    sqlx::query("DELETE FROM messages WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting messages: {}", e))?;

    sqlx::query("DELETE FROM private_chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting private chats: {}", e))?;

    sqlx::query("DELETE FROM group_chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting group chats: {}", e))?;

    sqlx::query("DELETE FROM chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting chat: {}", e))?;

    tx.commit()
        .await
        .map_err(|e| format!("Transaction commit failed: {}", e))?;

    Ok(())
}

// Returns all chats from the current profile
#[tauri::command]
pub async fn get_chats() -> Result<Vec<ChatInfo>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = utils::get_profile_name().await;

    let chats: Vec<ChatInfo> = sqlx::query_as::<_, ChatInfo>(
        r#"
        SELECT
          chat_id,
          chat_name,
          chat_type
        FROM chats
        WHERE chat_profil = ?1
        ORDER BY last_updated DESC
    "#,
    )
    .bind(current_profile)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to load chats: {}", e))?;

    Ok(chats)
}

// Get enc messages from database given a chat id and decrypts them using the global key
#[tauri::command]
pub async fn get_messages(chat_id: &str) -> Result<Vec<Message>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");
    let key = &keys.global_key;

    let mut messages: Vec<Message> = sqlx::query_as::<_, Message>(
        "SELECT * FROM messages WHERE chat_id = ?1 ORDER BY timestamp DESC LIMIT 100",
    )
    .bind(chat_id)
    .fetch(db)
    .try_collect()
    .await
    .map_err(|e| format!("Failed to get messages: {}", e))?;

    messages.reverse();

    let mut decrypted_messages = Vec::new();
    for mut msg in messages {
        let encrypted_buffer = hex::decode(msg.content)
            .map_err(|_| "Failed to parse encrypted message content as hex")?;

        match crypto::utils::decrypt_message(&encrypted_buffer, &key).await {
            Ok(decrypted) => {
                msg.content = decrypted;
                decrypted_messages.push(msg);
            }
            Err(_) => return Err("Decryption failed".into()),
        }
    }
    Ok(decrypted_messages)
}

// Create and save a profil given the credentials
#[tauri::command]
pub async fn create_profil(
    name: &str,
    mut password: String,
    mut phrase: String,
) -> Result<(), String> {
    let mnemonic = Mnemonic::parse_normalized(&phrase).map_err(|_| "Invalid recovery phrase")?;
    let mut seed = mnemonic.to_seed("");

    phrase.zeroize();

    let ed25519_keys = Ed25519KeyPair::from_seed_unchecked(&seed[32..])
        .map_err(|_| "Failed to generate Ed25519 key pair".to_string())?;

    let dilithium_keys = pqc_dilithium::Keypair::generate(&seed[..32]);

    seed.zeroize();

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let full_hash_input = [
        &dilithium_keys.public[..],
        &ed25519_keys.public_key().as_ref()[..],
        &nonce[..],
    ]
    .concat();
    let user_id = utils::create_user_id_hash(&full_hash_input);

    let hashed_password =
        bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

    let mut key = crypto::keys::generate_pbkdf2_key(&password)?;
    password.zeroize();

    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    sqlx::query(
        "INSERT INTO profiles 
         (dilithium_public, dilithium_private, ed25519, nonce, user_id, password_hash, profile_name) 
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(crypto::utils::encrypt_data(&dilithium_keys.public, &key).await)
        .bind(crypto::utils::encrypt_data(dilithium_keys.expose_secret(), &key).await)
        .bind(crypto::utils::encrypt_data(&seed[32..], &key).await)
        .bind(crypto::utils::encrypt_data(&nonce, &key).await)
        .bind(user_id)
        .bind(hashed_password)
        .bind(name)
        .execute(db)
        .await
        .map_err(|e| format!("Error inserting profile: {}", e))?;
    key.zeroize();
    Ok(())
}

// Set the name of the current profile
#[tauri::command]
pub async fn set_profile_name(name: String) {
    let mut profile_name = PROFILE_NAME.lock().await;
    *profile_name = name;
}

// Create a new private chat with the specified user id
#[tauri::command]
pub async fn create_private_chat(name: &str, dst_user_id: &str) -> Result<String, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_profile = utils::get_profile_name().await;
    let current_time = chrono::Utc::now().timestamp();

    let kyber_keys = safe_pqc_kyber::keypair(&mut OsRng, None);

    let mut settings = crate::utils::settings::PrivateChatSettings::default();
    settings.nickname = name.to_string();
    let settings_bytes = bincode::serialize(&settings).unwrap();
    
    sqlx::query("INSERT INTO chats (chat_id, chat_name, chat_type, last_updated, chat_profil) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(name)
        .bind("private")
        .bind(current_time)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    sqlx::query("INSERT INTO private_chats (chat_id, dst_user_id, perso_kyber_secret, perso_kyber_public, settings) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(dst_user_id)
        .bind(kyber_keys.secret.to_vec())
        .bind(kyber_keys.public.to_vec())
        .bind(settings_bytes)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    Ok(chat_id)
}

// Verify if the shared secret was already etablished return true if yes
#[tauri::command]
pub async fn has_shared_secret(chat_id: &str) -> Result<Option<bool>, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT COUNT(*), shared_secret FROM private_chats WHERE chat_id = ?")
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
