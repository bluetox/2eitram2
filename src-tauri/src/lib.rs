use blake3::Hasher;
use network::client::TcpClient;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use ring::signature::KeyPair;
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::env;
use std::sync::Arc;
use tauri::{AppHandle, Manager as _};
use tokio::sync::Mutex;

mod crypto;
mod database;
mod groups;
mod network;
mod utils;

pub static GLOBAL_STORE: OnceCell<Arc<Mutex<AppHandle>>> = OnceCell::new();
pub static PROFILE_NAME: once_cell::sync::Lazy<Mutex<String>> =
    once_cell::sync::Lazy::new(|| Mutex::new(String::new()));

static GLOBAL_CLIENT: Lazy<Mutex<Option<TcpClient>>> = Lazy::new(|| Mutex::new(None));
static GLOBAL_KEYS: Lazy<Mutex<Option<crypto::objects::Keys>>> = Lazy::new(|| Mutex::new(None));

pub static GLOBAL_DB: OnceCell<Pool<Sqlite>> = OnceCell::new();

#[tauri::command]
async fn terminate_any_client() {
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;

    if let Some(tcp_client) = tcp_guard.as_mut() {
        tcp_client.shutdown().await.unwrap();
        *tcp_guard = None;
    }
}

#[derive(serde::Deserialize)]
struct FrameData {
    data: Vec<u8>,
    width: usize,
    height: usize,
}

#[tauri::command]
async fn handle_frame_rgba(mut frame: FrameData, chat_id: String) {
    let user_id = database::private_chat::get_dst_id_from_chat_id(&chat_id)
        .await
        .unwrap();
    let mut modified_data = vec![0xF0, 0x00, 0x00, 0x00, 0x00];

    let mut hasher = Hasher::new();
    hasher.update(&frame.data);
    let _ = hasher.finalize();

    let dest_id_bytes = hex::decode(user_id).unwrap();

    modified_data.extend_from_slice(&dest_id_bytes);
    modified_data
        .extend_from_slice(&crypto::utils::encrypt_data(&frame.data, &[0u8; 32].to_vec()).await);

    let total_size = modified_data.len() as u32;

    modified_data[1..5].copy_from_slice(&total_size.to_le_bytes());

    frame.data = modified_data;

    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;

    if let Some(tcp_client) = tcp_guard.as_mut() {
        tcp_client.write(&frame.data).await
    } else {
        println!("No existing TCP client found");
    }
}

#[tauri::command]
async fn generate_dilithium_keys(password: &str) -> Result<String, String> {
    terminate_any_client().await;
    let keys = crypto::keys::load_keys(password)
        .await
        .map_err(|_| "Failed to load keys".to_string())?;

    let full_hash_input = [
        &keys.dilithium_keys.public[..],
        &keys.ed25519_keys.public_key().as_ref()[..],
        &keys.nonce[..],
    ]
    .concat();

    let mut key_guard = GLOBAL_KEYS.lock().await;
    *key_guard = Some(keys);
    drop(key_guard);

    let mut tcp_client = TcpClient::new();
    tcp_client
        .connect()
        .await
        .map_err(|e| format!("Failed to create tcp client: {}", e))?;

    let mut tcp_guard = GLOBAL_CLIENT.lock().await;
    if tcp_guard.is_none() {
        *tcp_guard = Some(tcp_client);
    } else {
        tcp_client.shutdown().await.unwrap();
        *tcp_guard = None;
        *tcp_guard = Some(tcp_client);
    }

    let user_id = utils::create_user_id_hash(&full_hash_input);

    Ok(user_id)
}

async fn setup_app_state(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_db(app).await;
    let guarded = Arc::new(Mutex::new(app.clone()));
    GLOBAL_STORE
        .set(guarded.clone())
        .expect("GLOBAL_STORE was already set");
    GLOBAL_DB
        .set(db.clone())
        .expect("Failed to set global DB. It may have been set already.");
    println!("Successfully initialised DB");
    Ok(())
}

pub async fn setup_db(app: &AppHandle) -> sqlx::Pool<sqlx::Sqlite> {
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
    let mut builder = tauri::Builder::default();

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    }

    builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            generate_dilithium_keys,
            network::commands::send_message,
            network::commands::establish_ss,
            network::commands::send_group_message,

            database::commands::get_chats,
            database::commands::get_messages,
            database::commands::set_profile_name,
            database::commands::create_profil,
            database::commands::create_private_chat,
            database::commands::get_profiles,
            database::commands::has_shared_secret,
            database::commands::delete_chat,

            groups::commands::create_groupe,
            groups::commands::add_group_member,

            crypto::keys::generate_mnemonic,
            crate::utils::settings::get_params,

            terminate_any_client,
            handle_frame_rgba
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
