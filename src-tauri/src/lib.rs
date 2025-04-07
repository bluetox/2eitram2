use modules::tcp::Client;
use once_cell::sync::OnceCell;
use pqc_dilithium::*;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use std::env;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tauri::{AppHandle, Manager as _};
use tauri::Wry;
use tokio::sync::Mutex;
mod modules;
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePoolOptions, Pool, Sqlite};

pub static GLOBAL_STORE: OnceCell<Mutex<Arc<tauri_plugin_store::Store<Wry>>>> = OnceCell::new();
pub static PROFILE_NAME: once_cell::sync::Lazy<Mutex<String>> = once_cell::sync::Lazy::new(|| Mutex::new(String::new()));

lazy_static::lazy_static! {
    pub static ref SHARED_SECRETS: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
}
lazy_static::lazy_static! {
    pub static ref ENCRYPTION_KEY: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
}
lazy_static::lazy_static! {
    pub static ref CLIENT: Arc<Mutex<modules::tcp::Client>> = Arc::new(Mutex::new(Client::new()));
}
lazy_static::lazy_static! {
    pub static ref KEYS : Arc<Mutex<Option<modules::objects::Keys>>> = Arc::new(Mutex::new(None));
}
pub static GLOBAL_DB: OnceCell<Pool<Sqlite>> = OnceCell::new();

#[tauri::command]
async fn generate_dilithium_keys(app: tauri::AppHandle, password: &str) -> Result<(), String> {
    match modules::handle_keys::load_keys(&password).await {
        Ok(keys) => {
            let full_hash_input = [
                &keys.dilithium_keys.public[..],
                &keys.ed25519_keys.public_key().as_ref()[..],
                &keys.nonce[..],
            ]
            .concat();
            let user_id = modules::utils::create_user_id_hash(&full_hash_input);
    
            println!("{}", user_id);

            {
                let mut keys_lock = KEYS.lock().await;
                *keys_lock = Some(keys);
            }

            let new_client = Client::new();
            new_client.connect(&app).await.unwrap();

            {
                let mut client_lock = CLIENT.lock().await;
                client_lock.shutdown().await;
                *client_lock = new_client;
            }

            return Ok(());
        }
        _ => println!("error"),
    }
    let rng = SystemRandom::new();
    let mut kyber_rng = rand::rngs::OsRng;
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "Failed to generate Ed25519 key pair".to_string())?;
    let ed25519_keys: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| "Failed to parse Ed25519 key pair".to_string())?;

    let dilithium_keys: Keypair = Keypair::generate();
    let mut nonce = [0u8; 16];
    SecureRandom::fill(&rng, &mut nonce)
        .map_err(|_| "Failed to generate random bytes".to_string())?;

    let kyber_keys = pqc_kyber::keypair(&mut kyber_rng).unwrap();

    let full_hash_input = [
        &dilithium_keys.public[..],
        &ed25519_keys.public_key().as_ref()[..],
        &nonce[..],
    ]
    .concat();
    let user_id = modules::utils::create_user_id_hash(&full_hash_input);
    println!("{}", user_id);
    let keys = modules::objects::Keys {
        dilithium_keys,
        ed25519_keys,
        kyber_keys,
        nonce,
    };
    
    {
        let mut keys_lock = KEYS.lock().await;
        *keys_lock = Some(keys);
    }

    let new_client = Client::new();
    new_client.connect(&app).await.unwrap();
    {
        let mut client_lock = CLIENT.lock().await;
        client_lock.shutdown().await;
        *client_lock = new_client;
    }
    let db = GLOBAL_DB
        .get()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let current_profile = modules::utils::get_profile_name().await;
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash password");
    {
        let mut key = ENCRYPTION_KEY.lock().await;
        *key = modules::handle_keys::generate_pbkdf2_key(password);
    
    sqlx::query(
        "UPDATE profiles 
         SET dilithium_public = ?, 
            dilithium_private = ?, 
            kyber_public = ?,
            kyber_private = ?,
            ed25519 = ?,
            nonce = ?,
            user_id = ?,
            password_hash = ?
         WHERE profile_name = ?"
    )
        .bind(modules::encryption::encrypt_data(&dilithium_keys.public, &key).await)
        .bind(modules::encryption::encrypt_data(dilithium_keys.expose_secret(), &key).await)
        .bind(modules::encryption::encrypt_data(&kyber_keys.public, &key).await)
        .bind(modules::encryption::encrypt_data(&kyber_keys.secret, &key).await)
        .bind(modules::encryption::encrypt_data(pkcs8_bytes.as_ref(), &key).await)
        .bind(modules::encryption::encrypt_data(&nonce, &key).await)
        .bind(user_id)
        .bind(hashed_password)
        .bind(current_profile)
        .execute(db)
        .await
        .map_err(|e| format!("Error updating shared secret: {}", e))?;
    }
    Ok(())
}

async fn setup_app_state(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_db(app).await;
    GLOBAL_DB
        .set(db.clone())
        .expect("Failed to set global DB. It may have been set already.");
    app.manage(modules::objects::AppState { db });
    println!("Successfully initialised DB");
    Ok(())
}

pub async fn setup_db(app: &AppHandle) -> modules::objects::Db {
    let mut path = app.path().app_data_dir().expect("failed to get data_dir");
    println!("{:?}", &path);

    match std::fs::create_dir_all(path.clone()) {
        Ok(_) => {}
        Err(err) => {
            panic!("error creating directory {}", err);
        }
    };

    path.push("db.sqlite");

    Sqlite::create_database(
        format!(
            "sqlite:{}",
            path.to_str().expect("path should be something")
        )
        .as_str(),
    )
    .await
    .expect("failed to create database");

    let db = SqlitePoolOptions::new()
        .connect(path.to_str().unwrap())
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    db
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            generate_dilithium_keys,
            modules::tcp::send_message,
            modules::database::add_chat,
            modules::database::get_chats,
            modules::database::save_message,
            modules::database::get_messages,
            modules::database::get_profiles,
            modules::database::has_shared_secret,
            modules::tcp::establish_ss,
            modules::database::set_profile_name,
            modules::database::delete_chat,
            modules::database::create_profil,
            modules::database::load_shared_secrets
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = setup_app_state(&app_handle).await {
                    eprintln!("Error setting up app state: {}", e);
                }
            });
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}