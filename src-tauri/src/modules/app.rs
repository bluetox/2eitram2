use super::{handle_keys, tcp, objects};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppCore {
    keys: Arc<Mutex<Option<objects::Keys>>>,
    tcp_client: Arc<Mutex<tcp::TcpClient>>,
    encryption_key: Arc<Mutex<Vec<u8>>>,
}

impl AppCore {
    pub async fn new(password: &str) -> Self {
        let app_keys = handle_keys::load_keys(password).await.ok();
        let tcp_client = tcp::TcpClient::new();

        AppCore {
            keys: Arc::new(Mutex::new(app_keys)),
            tcp_client: Arc::new(Mutex::new(tcp_client)),
            encryption_key: Arc::new(Mutex::new(Vec::new()))
        }
    }
}