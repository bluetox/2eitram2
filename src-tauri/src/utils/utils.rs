use sha2::{Digest, Sha256};

pub fn create_user_id_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub async fn get_profile_name() -> String {
    super::super::PROFILE_NAME.lock().await.clone()
}

