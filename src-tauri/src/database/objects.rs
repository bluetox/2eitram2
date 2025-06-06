#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

#[derive(Debug, Serialize, FromRow)]
pub struct Profile {
    pub profile_id: String,
    pub profile_name: String,
}

#[derive(Debug, Serialize, FromRow)]
pub struct ChatInfo {
    pub chat_id: String,
    pub chat_name: String,
    pub chat_type: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Message {
    pub message_id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub message_type: String,
    pub content: String,
}

#[derive(Debug, FromRow)]
pub struct KyberKeys {
    pub perso_kyber_public: Vec<u8>,
    pub perso_kyber_secret: Vec<u8>,
}
