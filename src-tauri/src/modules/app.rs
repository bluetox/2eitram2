use super::objects;
use std::sync::Arc;
use tokio::sync::Mutex;
use super::super::network::client::TcpClient;

pub struct AppCore {
    keys: Arc<Mutex<Option<objects::Keys>>>,
    tcp_client: Arc<Mutex<TcpClient>>,
    encryption_key: Arc<Mutex<Vec<u8>>>,
}

impl AppCore {
    pub async fn new(password: &str) -> Self {
        let app_keys = crate::encryption::keys::load_keys(password).await.ok();
        let tcp_client = TcpClient::new();

        AppCore {
            keys: Arc::new(Mutex::new(app_keys)),
            tcp_client: Arc::new(Mutex::new(tcp_client)),
            encryption_key: Arc::new(Mutex::new(Vec::new()))
        }
    }
}