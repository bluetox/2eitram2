use minimalist_pq_mls::group::GroupState;
use rand::rngs::OsRng;
use sqlx::Row;

pub async fn save_new_created_group(
    group: GroupState,
    group_id: &str,
    group_name: &str,
    kyber_keys: &safe_pqc_kyber::Keypair,
    group_owner: &str,
) -> Result<(), String> {
    let raw = bincode::serialize(&group).unwrap();
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_profile = crate::utils::get_profile_name().await;
    let current_time = chrono::Utc::now().timestamp();

    let root_secret = group.get_root();

    sqlx::query("INSERT INTO chats (chat_id, chat_name, chat_type, last_updated, chat_profil) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(group_name)
        .bind("group")
        .bind(current_time)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    sqlx::query("INSERT INTO group_chats (chat_id, group_id, group_owner, perso_kyber_secret, perso_kyber_public, root_secret, group_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")
        .bind(&chat_id)
        .bind(group_id)
        .bind(group_owner)
        .bind(kyber_keys.secret.to_vec())
        .bind(kyber_keys.public.to_vec())
        .bind(&root_secret)
        .bind(&raw)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    Ok(())
}

pub async fn save_new_group(
    group_id: &str,
    group_name: &str,
    group_owner: &str,
) -> Result<Vec<u8>, String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;
    let existing = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM group_chats gc
        JOIN chats c ON c.chat_id = gc.chat_id
        WHERE gc.group_id = ?1 AND c.chat_profil = ?2
        "#,
    )
    .bind(group_id)
    .bind(&current_profile)
    .fetch_one(db)
    .await
    .map_err(|e| format!("DB error checking for duplicate group: {}", e))?;

    if existing > 0 {
        println!("existing");
        return Err(format!(
            "Group '{}' already exists for profile '{}'",
            group_id, current_profile
        ));
    }

    let chat_id = uuid::Uuid::new_v4().to_string();
    let current_time = chrono::Utc::now().timestamp();
    let kyber_keypair = safe_pqc_kyber::keypair(&mut OsRng, None);

    sqlx::query("INSERT INTO chats (chat_id, chat_name, chat_type, last_updated, chat_profil) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(group_name)
        .bind("group")
        .bind(current_time)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving chat: {}", e))?;

    sqlx::query("INSERT INTO group_chats (chat_id, group_id, group_owner, perso_kyber_secret, perso_kyber_public) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&chat_id)
        .bind(group_id)
        .bind(group_owner)
        .bind(kyber_keypair.secret.to_vec())
        .bind(kyber_keypair.public.to_vec())
        .execute(db)
        .await
        .map_err(|e| format!("Error saving group chat: {}", e))?;

    Ok(kyber_keypair.public.to_vec())
}

pub async fn load_group_from_id(group_id: &str) -> Result<GroupState, String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;

    let row = sqlx::query(
        r#"
        SELECT gc.group_data FROM group_chats gc
        JOIN chats c ON c.chat_id = gc.chat_id
        WHERE gc.group_id = ?1 AND c.chat_profil = ?2
        "#,
    )
    .bind(group_id)
    .bind(&current_profile)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to get group data: {}", e))?;

    let row = row.ok_or_else(|| "Group not found for this profile".to_string())?;

    let data: Vec<u8> = row
        .try_get("group_data")
        .map_err(|e| format!("Failed to extract group_data: {}", e))?;

    let group: GroupState = bincode::deserialize(&data)
        .map_err(|e| format!("Failed to deserialize group data: {}", e))?;

    Ok(group)
}

pub async fn save_group_state(group: GroupState, group_id: &str) -> Result<(), String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;

    let row = sqlx::query(
        r#"
        SELECT gc.chat_id FROM group_chats gc
        JOIN chats c ON c.chat_id = gc.chat_id
        WHERE gc.group_id = ?1 AND c.chat_profil = ?2
        "#,
    )
    .bind(&group_id)
    .bind(&current_profile)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error finding group: {}", e))?;

    let row = row.ok_or_else(|| "Group not found for this profile".to_string())?;

    let chat_id: String = row
        .try_get("chat_id")
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    let data = bincode::serialize(&group)
        .map_err(|e| format!("Failed to serialize group state: {}", e))?;

    sqlx::query("UPDATE group_chats SET group_data = ?1 WHERE chat_id = ?2")
        .bind(data)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Failed to update group state: {}", e))?;

    Ok(())
}

pub async fn group_sk_from_group_id(group_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;

    let row = sqlx::query(
        r#"
        SELECT gc.perso_kyber_secret, gc.perso_kyber_public FROM group_chats gc
        JOIN chats c ON c.chat_id = gc.chat_id
        WHERE gc.group_id = ?1 AND c.chat_profil = ?2
        "#,
    )
    .bind(group_id)
    .bind(current_profile)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database query error: {}", e))?;

    if let Some(row) = row {
        let pk: Vec<u8> = row
            .try_get("perso_kyber_public")
            .map_err(|e| format!("Column extraction error (public): {}", e))?;
        let sk: Vec<u8> = row
            .try_get("perso_kyber_secret")
            .map_err(|e| format!("Column extraction error (secret): {}", e))?;

        Ok((sk, pk))
    } else {
        Err("Group not found for this profile".to_string())
    }
}

pub async fn group_from_chat_id(chat_id: &str) -> Result<GroupState, String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let row = sqlx::query(
        r#"
        SELECT group_data FROM group_chats WHERE chat_id = ?
        "#,
    )
    .bind(chat_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to get group data: {}", e))?;

    let row = row.ok_or_else(|| "Group not found for this profile".to_string())?;

    let data: Vec<u8> = row
        .try_get("group_data")
        .map_err(|e| format!("Failed to extract group_data: {}", e))?;

    let group: GroupState = bincode::deserialize(&data)
        .map_err(|e| format!("Failed to deserialize group data: {}", e))?;

    Ok(group)
}

pub async fn chat_id_from_group_id(group_id: &str) -> Result<String, String> {
    let db = crate::GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let current_profile = crate::utils::get_profile_name().await;

    let row = sqlx::query(
        r#"
        SELECT gc.chat_id FROM group_chats gc
        JOIN chats c ON c.chat_id = gc.chat_id
        WHERE gc.group_id = ?1 AND c.chat_profil = ?2
        "#,
    )
    .bind(group_id)
    .bind(&current_profile)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to get chat_id: {}", e))?
    .ok_or_else(|| "Chat ID not found for this group".to_string())?;

    let chat_id: String = row
        .try_get("chat_id")
        .map_err(|e| format!("Failed to extract chat_id: {}", e))?;

    Ok(chat_id)
}
