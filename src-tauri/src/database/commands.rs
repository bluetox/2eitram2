use crate::modules::{
    objects,
    utils
};
use crate::ENCRYPTION_KEY;
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
    let db = crate::GLOBAL_DB
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
    
    sqlx::query("DELETE FROM chats WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&*db)
        .await
        .map_err(|e| format!("Error deleting chat: {}", e))?;
    
    Ok(())
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
    
            match crate::encryption::utils::decrypt_message(&encrypted_buffer, &key).await {
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

    let kyber_keys = safe_pqc_kyber::keypair(&mut kyber_rng);

    let full_hash_input = [
        &dilithium_keys.public[..],
        &ed25519_keys.public_key().as_ref()[..],
        &nonce[..],
    ]
    .concat();
    let user_id = utils::create_user_id_hash(&full_hash_input);

    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let hashed_password = bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

    let mut key = crate::encryption::keys::generate_pbkdf2_key(&password)?;
    password.zeroize();
    sqlx::query(
        "INSERT INTO profiles 
         (dilithium_public, dilithium_private, kyber_public, kyber_private, ed25519, nonce, user_id, password_hash, profile_name) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(crate::encryption::utils::encrypt_data(&dilithium_keys.public, &key).await)
        .bind(crate::encryption::utils::encrypt_data(dilithium_keys.expose_secret(), &key).await)
        .bind(crate::encryption::utils::encrypt_data(&kyber_keys.public, &key).await)
        .bind(crate::encryption::utils::encrypt_data(&kyber_keys.secret, &key).await)
        .bind(crate::encryption::utils::encrypt_data(pkcs8_bytes.as_ref(), &key).await)
        .bind(crate::encryption::utils::encrypt_data(&nonce, &key).await)
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
        let mut profile_name = crate::PROFILE_NAME.lock().await;
        *profile_name = name;
    }
}

#[tauri::command]
pub async fn add_chat(
    name: &str,
    dst_user_id: &str,
) -> Result<String, String> {
    let db = crate::GLOBAL_DB
    .get()
    .ok_or_else(|| "Database not initialized".to_string())?;
    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_profile = utils::get_profile_name().await;
    let current_time = chrono::Utc::now().timestamp();
    let mut rng = OsRng;
    let kyber_keys = safe_pqc_kyber::keypair(&mut rng);

    sqlx::query("INSERT INTO chats (chat_id, chat_name, dst_user_id, chat_type, last_updated, chat_profil, perso_kyber_secret, perso_kyber_public) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
        .bind(&chat_id)
        .bind(name)
        .bind(dst_user_id)
        .bind("convo")
        .bind(current_time)
        .bind(current_profile)
        .bind(kyber_keys.secret.to_vec())
        .bind(kyber_keys.public.to_vec())
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    println!("Saved chat {} for user {} successfully", name, dst_user_id);

    Ok(chat_id)
}

#[tauri::command]
pub async fn has_shared_secret(chat_id: &str) -> Result<Option<bool>, String> {
    let db = crate::GLOBAL_DB
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

#[tauri::command]
pub async fn save_message(
    state: tauri::State<'_, objects::AppState>,
    chat_id: &str,
    sender_id: &str,
    message: String,
) -> Result<(), String> {
    let db = &state.db;
    let key = ENCRYPTION_KEY.lock().await;
    
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
        .bind(sender_id)
        .bind("sent")
        .bind(encrypted_message)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving todo: {}", e))?;
    Ok(())
}