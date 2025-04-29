use crate::{
    utils,
    encryption,
    GLOBAL_DB,
    PROFILE_NAME,
    modules::objects
};

use rand::rngs::OsRng;
use futures::TryStreamExt;
use bip39::Mnemonic;
use zeroize::Zeroize;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};

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
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let mut tx = db.begin().await.map_err(|e| format!("Transaction start failed: {}", e))?;

    // 1. Delete related messages
    sqlx::query("DELETE FROM messages WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting messages: {}", e))?;

    // 2. Delete related private chats
    sqlx::query("DELETE FROM private_chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Error deleting private chats: {}", e))?;

    // 3. Delete related group chats
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

    tx.commit().await.map_err(|e| format!("Transaction commit failed: {}", e))?;

    Ok(())
}


#[tauri::command]
pub async fn get_chats(
    state: tauri::State<'_, objects::AppState>
) -> Result<Vec<objects::ChatInfo>, String> {
    let db = &state.db;
    let current_profile = utils::get_profile_name().await;

    let chats: Vec<objects::ChatInfo> = sqlx::query_as::<_, objects::ChatInfo>(r#"
        SELECT
          c.chat_id,
          c.chat_name,
          p.dst_user_id
        FROM chats AS c
        LEFT JOIN private_chats AS p
          ON p.chat_id = c.chat_id
        WHERE c.chat_profil = ?1
        ORDER BY c.last_updated DESC
    "#)
    .bind(current_profile)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to load chats: {}", e))?;

    Ok(chats)
}

#[tauri::command]
pub async fn get_messages(
    state: tauri::State<'_, objects::AppState>,
    chat_id: &str,
) -> Result<Vec<objects::Message>, String> {
    let db = &state.db;

    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");
    let key = &keys.global_key;

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
    
            match encryption::utils::decrypt_message(&encrypted_buffer, &key).await {
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
pub async fn create_profil(name: &str, mut password: String, mut phrase: String) -> Result<(), String> {

    let rng = SystemRandom::new();

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

    let mut key = encryption::keys::generate_pbkdf2_key(&password)?;
    password.zeroize();
    sqlx::query(
        "INSERT INTO profiles 
         (dilithium_public, dilithium_private, ed25519, nonce, user_id, password_hash, profile_name) 
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(encryption::utils::encrypt_data(&dilithium_keys.public, &key).await)
        .bind(encryption::utils::encrypt_data(dilithium_keys.expose_secret(), &key).await)
        .bind(encryption::utils::encrypt_data(pkcs8_bytes.as_ref(), &key).await)
        .bind(encryption::utils::encrypt_data(&nonce, &key).await)
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

#[tauri::command]
pub async fn create_private_chat(
    name: &str,
    dst_user_id: &str,
) -> Result<String, String> {
    let db = GLOBAL_DB
    .get()
    .ok_or_else(|| "Database not initialized".to_string())?;
    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_profile = utils::get_profile_name().await;
    let current_time = chrono::Utc::now().timestamp();
    let mut rng = OsRng;

    sqlx::query("INSERT INTO chats (chat_id, chat_name, chat_type, last_updated, chat_profil) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(name)
        .bind("private")
        .bind(current_time)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;


    let kyber_keys = safe_pqc_kyber::keypair(&mut rng);

    sqlx::query("INSERT INTO private_chats (chat_id, dst_user_id, perso_kyber_secret, perso_kyber_public) VALUES (?1, ?2, ?3, ?4)")
        .bind(&chat_id)
        .bind(dst_user_id)
        .bind(kyber_keys.secret.to_vec())
        .bind(kyber_keys.public.to_vec())
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    Ok(chat_id)
}

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

pub async fn need_for_rekey(chat_id: &str) -> Result<bool, String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let result: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM messages WHERE chat_id = ? AND message_type = 'sent'"
    )
    .bind(chat_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to count messages: {}", e))?;

    Ok(matches!(result, Some((n,)) if n != 0 && n % 4 == 0))
}

pub async fn new_chat_keypair(
    keypair: &safe_pqc_kyber::Keypair,
    chat_id: &str
) -> Result<(), String> {
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    sqlx::query(
        "UPDATE private_chats SET perso_kyber_public = ?, perso_kyber_secret = ? WHERE chat_id = ?"
    )
    .bind(keypair.public.to_vec())
    .bind(keypair.secret.to_vec())
    .bind(chat_id)
    .execute(db)
    .await
    .map_err(|e| format!("Error upserting chat keypair: {}", e))?;

    Ok(())
}
