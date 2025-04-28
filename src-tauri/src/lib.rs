use once_cell::sync::OnceCell;
use ring::signature::KeyPair;
use std::env;
use std::sync::Arc;
use tauri::{AppHandle, Manager as _};
use tauri::Wry;
use tokio::sync::Mutex;
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePoolOptions, Pool, Sqlite};
use network::client::TcpClient;
mod modules;
mod network;
mod database;
mod encryption;
mod utils;

pub static GLOBAL_STORE: OnceCell<Mutex<Arc<tauri_plugin_store::Store<Wry>>>> = OnceCell::new();
pub static PROFILE_NAME: once_cell::sync::Lazy<Mutex<String>> = once_cell::sync::Lazy::new(|| Mutex::new(String::new()));

lazy_static::lazy_static! {
    pub static ref ENCRYPTION_KEY: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
}
lazy_static::lazy_static! {
    pub static ref TCP_CLIENT: Arc<Mutex<TcpClient>> = Arc::new(Mutex::new(TcpClient::new()));
}
lazy_static::lazy_static! {
    pub static ref KEYS : Arc<Mutex<Option<modules::objects::Keys>>> = Arc::new(Mutex::new(None));
}
pub static GLOBAL_DB: OnceCell<Pool<Sqlite>> = OnceCell::new();

//#[tauri::command]
//async fn create_group_chat(chat_name: String, members: Vec<String>) {
//    let creator_name = utils::get_profile_name().await;
//    let mut index = 0;
//    let mut root_key = vec![0u8; 32];
//    OsRng.fill_bytes(&mut root_key);
//    let mut group = mls_rust::GroupChat::create(creator_name.clone(), root_key);
//    group.print_root("Initial");
//
//    for user_id in &members {
//        if user_id.len() != 64 || hex::decode(user_id).is_err(){
//            return;
//        }
//    }
//    let group_id = uuid::Uuid::new_v4().to_string();
//    for user_id in &members{
//        let packet = crate::network::packet::create_add_chat_packet(&user_id, &chat_name, &group_id).await;
//        {
//            let mut client = TCP_CLIENT.lock().await;
//            client.send_group_invite(packet).await;
//        }
//    }
//}

#[tauri::command]
async fn generate_dilithium_keys(app: tauri::AppHandle, password: &str) -> Result<String, String> {
    match encryption::keys::load_keys(&password).await {
        Ok(keys) => {
            let full_hash_input = [
                &keys.dilithium_keys.public[..],
                &keys.ed25519_keys.public_key().as_ref()[..],
                &keys.nonce[..],
            ]
            .concat();
            let user_id = utils::create_user_id_hash(&full_hash_input);
    
            {
                let mut keys_lock = KEYS.lock().await;
                *keys_lock = Some(keys);
            }

            let mut new_client = TcpClient::new();
            new_client.connect(&app).await.unwrap();

            {
                let mut client_lock = TCP_CLIENT.lock().await;
                client_lock.shutdown().await;
                *client_lock = new_client;
            }

            return Ok(user_id);
        }
        Err(e) => {
            println!("error : {:?}", e);
            return Err("Failed to load keys".to_string());
        }
    }
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
            network::commands::send_message,
            network::commands::establish_ss,

            database::commands::get_chats,
            database::commands::get_messages,
            database::commands::set_profile_name,
            database::commands::create_profil,

            database::commands::create_private_chat,
            database::commands::get_profiles,
            database::commands::has_shared_secret,
            database::commands::delete_chat,

            encryption::keys::generate_mnemonic
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