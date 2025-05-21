use super::utils::send_group_invite;
use rand::{rngs::OsRng, RngCore};
use ring::signature::KeyPair;

#[tauri::command]
pub async fn create_groupe(members: Vec<String>, group_name: String) {
    let kyber_keys = safe_pqc_kyber::keypair(&mut OsRng, None);
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");
    let user_id = keys.calculate_user_id();

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    let group_id = uuid::Uuid::new_v4().to_string();
    let mut group = minimalist_pq_mls::group::GroupState::new(&group_id);
    group.add_member(
        kyber_keys.public.to_vec(),
        keys.dilithium_keys.public.to_vec(),
        keys.ed25519_keys.public_key().as_ref().to_vec(),
        &user_id,
        secret.to_vec(),
        None,
    );

    crate::database::group_chat::save_new_created_group(
        group,
        &group_id,
        &group_name,
        &kyber_keys,
        &user_id,
    )
    .await
    .unwrap();
    drop(keys_lock);
    for user_id in &members {
        send_group_invite(&user_id, &group_id, &group_name).await;
    }
}

#[tauri::command]
pub async fn add_group_member(chat_id: String, user_id: String, group_name: String) {
    let group = crate::database::group_chat::group_from_chat_id(&chat_id)
        .await
        .unwrap();
    let group_id = &group.group_id;

    send_group_invite(&user_id, &group_id, &group_name).await;
}
