use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
pub struct Keys {
    pub dilithium_keys: pqc_dilithium::Keypair,
    pub ed25519_keys: ring::signature::Ed25519KeyPair,
    pub kyber_keys: safe_pqc_kyber::Keypair,
    pub nonce: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Message {
    pub message_id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub message_type: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Chat {
    pub chat_id: String,
    pub chat_name: String,
    pub dst_user_id: String,
}


pub struct AppState {
    pub db: Db,
}
pub type Db = sqlx::Pool<sqlx::Sqlite>;

