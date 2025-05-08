use bytes::BytesMut;
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const NODE_ADDRESS: &str = "91.175.221.153";

pub struct TcpClient {
    write_half: Arc<Mutex<Option<tokio::io::WriteHalf<TcpStream>>>>,
    stop_flag: Arc<AtomicBool>,
    pub node_shared_secret: Arc<Mutex<Vec<u8>>>,
    listener: Option<tokio::task::JoinHandle<()>>
}

impl TcpClient {
    pub fn new() -> Self {
        Self {
            write_half: Arc::new(Mutex::new(None)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            node_shared_secret: Arc::new(Mutex::new(Vec::new())),
            listener: None,
        }
    }
    
    pub async fn connect(
        &mut self
    ) -> Result<(), String> {
        const NODE_PORT: u16 = 32775;
    
        let mut stream = TcpStream::connect(format!("{}:{}", NODE_ADDRESS, NODE_PORT)).await
            .map_err(|e| format!("Failed to connect to main node: {}", e))?;
    
        let get_nodes_packet = super::packet::create_get_nodes_packet().await;
        stream.write_all(&get_nodes_packet).await
            .map_err(|e| format!("Failed to write get node packet: {}", e))?;
    
        let mut chunk = vec![0u8; 2048];
        let bytes_read = stream.read(&mut chunk).await
            .map_err(|e| format!("Failed to read assigned nodes: {}", e))?;
        stream.shutdown().await
            .map_err(|e| format!("Failed shutdown socket: {}", e))?;
    
        chunk.truncate(bytes_read);
    
        let buffer_str = std::str::from_utf8(&chunk)
            .map_err(|_| "Invalid UTF-8 received from main node")?;
    
        let ips: Vec<String> = buffer_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
    
        let mut successful_connection = None;
        for ip in ips {
            match TcpStream::connect(format!("{}:{}", ip, NODE_PORT)).await {
                Ok(new_stream) => {
                    println!("Connected to node: {}", ip);
                    successful_connection = Some(new_stream);
                    break;
                }
                Err(e) => {
                    println!("Failed to connect to {}: {}", ip, e);
                }
            }
        }
    
        let stream = successful_connection.ok_or("Failed to connect to any nodes.".to_string())?;
    
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        {
            let ss = super::utils::establish_ss_with_node(&mut read_half, &mut write_half).await;
            let mut locked_ss = self.node_shared_secret.lock().await;
            *locked_ss = ss.clone();
            let buffer = super::packet::create_server_connect_packet(ss).await?;
            write_half.write_all(&buffer).await
                .map_err(|e| format!("Failed to write server_connect: {}", e))?;
        }
        {
            let mut current = self.write_half.lock().await;
            *current = Some(write_half);
        }
    
        let flag_clone = Arc::clone(&self.stop_flag);
        let handle = tokio::spawn(async move {
                if let Err(e) = super::utils::listen(&mut read_half, flag_clone).await {
                    eprintln!("Listener error: {:?}", e);
                }
            });
            self.listener = Some(handle);
    
        Ok(())
    }
    
    
    pub async fn send_message(
        &mut self, chat_id: &str, dst_id_hexs: &str, message_string: &str
    ) {
        {
            let nss = self.get_node_shared_secret().await;
            let ss = crate::crypto::keys::ratchet_forward(&"send_root_secret", &chat_id).await.unwrap();
            let encrypted_packet = crate::network::packet::create_send_message_packet(dst_id_hexs, message_string, &ss.to_vec(), &nss)
            .await
            .unwrap();
        {
            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(&encrypted_packet).await.unwrap();
            }
        }  
        }
    }
    pub async fn write_enc(
        &mut self, raw_packet: &Vec<u8>
    ) {
        let nss = self.get_node_shared_secret().await;
        let encrypted_packet = crate::crypto::utils::encrypt_packet(raw_packet, &nss).await;
        let mut locked = self.write_half.lock().await;
        if let Some(ref mut writer) = *locked {
            writer.write_all(&encrypted_packet).await.unwrap();
        }
    }

    pub async fn send_kyber_key(
        &mut self, dst_id_bytes: Vec<u8>, kyber_keys: &safe_pqc_kyber::Keypair
    ) {
        let keys_lock = crate::GLOBAL_KEYS.lock().await;
        let keys = keys_lock.as_ref().expect("Keys not initialized");
    
        let kyber_public_key = kyber_keys.public;

        let dilithium_public_key = keys.dilithium_keys.public.clone();
        let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();
        let nonce = keys.nonce;
        
        let current_time = SystemTime::now();
        let duration_since_epoch = current_time
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
    
        let timestamp = duration_since_epoch.as_secs() as u64;
        let timestamp_bytes = timestamp.to_le_bytes();
    
        let mut sign_part = BytesMut::with_capacity(
            dilithium_public_key.len()
                + ed25519_public_key.len()
                + dst_id_bytes.len()
                + nonce.len()
                + timestamp_bytes.len()
                + kyber_public_key.len(),
        );
        sign_part.extend_from_slice(&dilithium_public_key);
        sign_part.extend_from_slice(&ed25519_public_key);
        sign_part.extend_from_slice(&dst_id_bytes);
        sign_part.extend_from_slice(&nonce);
        sign_part.extend_from_slice(&timestamp_bytes);
        sign_part.extend_from_slice(&kyber_public_key);
    
        let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
        let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();
        drop(keys_lock);
    
        let mut raw_packet = BytesMut::with_capacity(
            5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
        );
    
        raw_packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00]);
        raw_packet.extend_from_slice(&dilithium_signature);
        raw_packet.extend_from_slice(&ed25519_signature);
        raw_packet.extend_from_slice(&sign_part);
        {   
            let node_shared_secret = self.get_node_shared_secret().await;
            let encrypted_packet = crate::crypto::utils::encrypt_packet(&raw_packet, &node_shared_secret).await;

            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(&encrypted_packet).await.unwrap();
            }
        }
    }

    pub async fn get_node_shared_secret(
        &self
    ) -> Vec<u8> {
        self.node_shared_secret.lock().await.to_vec()
    }

    pub async fn write(
        &mut self, data: &Vec<u8>
    ) {
        {
            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(data).await.unwrap();
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), String> {
        self.stop_flag.store(true, Ordering::Relaxed);
    
        let writer_opt = {
            let mut guard = self.write_half.lock().await;
            guard.take()
        };

        if let Some(handle) = self.listener.take() {
            let _ = handle.await;
        }

        if let Some(mut writer) = writer_opt {
            let _ = writer.shutdown().await;
        }

        Ok(())
    }
}