use super::handle;
use bytes::{Buf, BytesMut};
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Client {
    write_half: Arc<Mutex<Option<tokio::io::WriteHalf<TcpStream>>>>,
    pub node_shared_secret: Arc<Mutex<Vec<u8>>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            write_half: Arc::new(Mutex::new(None)),
            node_shared_secret: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn connect(&self, app: &AppHandle) -> io::Result<()> {
        let mut stream = TcpStream::connect("192.168.1.51:8081").await?;
        let get_nodes_packet = create_get_nodes_packet().await;
        stream.write_all(&get_nodes_packet).await?;

        let mut chunk = vec![0u8; 2048];
        let bytes_read = stream.read(&mut chunk).await?;

        stream.shutdown().await?;

        chunk.truncate(bytes_read);

        let buffer_str = match std::str::from_utf8(&chunk) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        let ips: Vec<String> = buffer_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let mut successful_connection = None;

        for ip in ips {
            match TcpStream::connect(format!("{}:8081", ip)).await {
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

        if let Some(stream) = successful_connection {
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            establish_ss_with_node(&mut read_half, &mut write_half).await;

            let buffer = create_server_connect_packet().await.unwrap();
            write_half.write_all(&buffer).await?;

            {
                let mut current = self.write_half.lock().await;
                *current = Some(write_half);
            }
            println!("Starting listener");
            tokio::spawn({
                let app = app.clone();
                async move {
                    listen(&mut read_half, &app).await.unwrap();
                }
            });
            
        } else {
            println!("Failed to connect to any nodes.");
        }

        Ok(())
    }
    
    pub async fn send_message(&mut self, dst_id_hexs: String, message_string: String) {
        let encrypted_packet = super::utils::create_send_message_packet(dst_id_hexs, message_string)
            .await;
        {
            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(&encrypted_packet).await.unwrap();
            }
        }  
    }

    pub async fn send_kyber_key(&mut self, dst_id_bytes: Vec<u8>) {
        let keys_lock = super::super::KEYS.lock().await;
        let keys = keys_lock.as_ref().expect("Keys not initialized");
        let kyber_public_key = keys.kyber_keys.public;
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
            let client = super::super::CLIENT.lock().await;
            let node_shared_secret = client.get_node_shared_secret().await;
            let encrypted_packet = super::encryption::encrypt_packet(&raw_packet, &node_shared_secret).await;
        
            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(&encrypted_packet).await.unwrap();
            }
        }
    }

    pub async fn get_node_shared_secret(&self) -> Vec<u8> {
        self.node_shared_secret.lock().await.to_vec()
    }

    pub async fn set_node_shared_secret(&mut self, ss: Vec<u8>) {
        let mut locked_ss = self.node_shared_secret.lock().await;
        *locked_ss = ss;
    }

    pub async fn write(&mut self, data: &Vec<u8>) {
        {
            let mut locked = self.write_half.lock().await;
            if let Some(ref mut writer) = *locked {
                writer.write_all(data).await.unwrap();
            }
        }
    }

    pub async fn shutdown(&mut self) {
        let mut locked = self.write_half.lock().await;
        if let Some(ref mut writer) = *locked {
            let _ = writer.shutdown().await;
            println!("Underlying TCP connection shut down.");
        }
    }
}

#[tauri::command]
pub async fn send_message(dst_id_hexs: String, message_string: String) {
    {
        let mut client = super::super::CLIENT.lock().await;
        client.send_message(dst_id_hexs, message_string).await;
    }
}

pub async fn create_get_nodes_packet() -> Vec<u8>{
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().ok_or("Keys not initialized").unwrap();
    
    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e)).unwrap();
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len()
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0x0a, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let total_size = raw_packet.len() as u16;
    raw_packet[1..3].copy_from_slice(&total_size.to_le_bytes());
    raw_packet.to_vec()
}

pub async fn establish_ss_with_node(read_half: &mut tokio::io::ReadHalf<TcpStream>, write_half:  &mut tokio::io::WriteHalf<TcpStream>) {
    let mut message = BytesMut::with_capacity(1573);
    let total_size =  1573 as u16;
    let mut rng =   rand::rngs::OsRng;
    let keypair = pqc_kyber::Keypair::generate(&mut rng).unwrap();

    message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    message[1..3].copy_from_slice(&total_size.to_le_bytes());
    message.extend_from_slice(&keypair.public);

    let _ = write_half.write_all(&message).await;

    let mut chunk = vec![0u8; 2048];
    let _response = read_half.read(&mut chunk).await;

    let ct = &chunk[5 .. 5 + 1568];

    let ss = pqc_kyber::decapsulate(ct, &keypair.secret).unwrap().to_vec();
    {
        let mut client = super::super::CLIENT.lock().await;
        client.set_node_shared_secret(ss).await;
    }
    
}

pub async fn create_server_connect_packet() -> Result<Vec<u8>, String> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().ok_or("Keys not initialized")?;
    
    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e))?;
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len()
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len()
    );
    raw_packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let client = super::super::CLIENT.lock().await;
    let node_shared_secret = client.get_node_shared_secret().await;
    let encrypted_packet = super::encryption::encrypt_packet(&raw_packet, &node_shared_secret).await;
    drop(client);
    
    Ok(encrypted_packet)
}

pub async fn send_cyphertext(dst_id_bytes: Vec<u8>, cyphertext: Vec<u8>) -> Vec<u8> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

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
            + cyphertext.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&cyphertext);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();
    drop(keys_lock);

    let mut raw_packet = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );

    raw_packet.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00]);
    raw_packet.extend_from_slice(&dilithium_signature);
    raw_packet.extend_from_slice(&ed25519_signature);
    raw_packet.extend_from_slice(&sign_part);

    let client = super::super::CLIENT.lock().await;
    let node_shared_secret = client.get_node_shared_secret().await;
    let encrypted_packet = super::encryption::encrypt_packet(&raw_packet, &node_shared_secret).await;
    drop(client);

    return encrypted_packet;
}

async fn listen(
    read_half: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    app: &AppHandle,
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut chunk = vec![0u8; 1024];
    loop {
        match read_half.read(&mut chunk).await {
            Ok(0) => {
                println!("Disconnected from server.");
                break;
            }
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);

                if buffer.len() < 3 {
                    println!("[ERROR] Invalid packet: too short");
                    buffer.clear();
                    continue;
                }

                let prefix = buffer[0];
                let payload_size_bytes = &buffer[1..3];
                let payload_size =
                    u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

                if buffer.len() < payload_size {
                    continue;
                }

                match prefix {
                    2 => {
                        let response = super::handle::handle_kyber(&buffer[..payload_size].to_vec()).await.unwrap();
                        {
                            let mut client = super::super::CLIENT.lock().await;
                            client.write(&response).await;
                        }
                    }
                    3 => {
                        if let Err(err) = handle::handle_ct(&buffer[..payload_size].to_vec()).await {
                            println!("Error handling ciphertext: {}", err);
                        }                        
                    }
                    4 => {
                        let _ = handle::handle_message(&buffer[..payload_size].to_vec(), app).await;
                    }
                    _ => {
                        println!("[ERROR] Invalid packet: unknown prefix {}", prefix);
                    }
                }

                buffer.advance(payload_size);
                
            }
            Err(e) => {
                eprintln!("Error reading from stream: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn establish_ss(dst_user_id: String) {
    {
        let mut client = super::super::CLIENT.lock().await;
        client.send_kyber_key(hex::decode(dst_user_id).unwrap()).await;
    }
}
