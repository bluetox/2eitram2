use crate::groups::tcp_handles;
use blake3::Hasher;
use bytes::{Buf, BytesMut};
use ring::signature::KeyPair;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Emitter;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn establish_ss_with_node(
    read_half: &mut tokio::io::ReadHalf<TcpStream>,
    write_half: &mut tokio::io::WriteHalf<TcpStream>,
) -> Vec<u8> {
    let mut message = BytesMut::with_capacity(1573);
    let total_size = 1573 as u16;
    let mut rng = rand::rngs::OsRng;
    let keypair = safe_pqc_kyber::keypair(&mut rng, None);

    message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    message[1..3].copy_from_slice(&total_size.to_le_bytes());
    message.extend_from_slice(&keypair.public);

    let _ = write_half.write_all(&message).await;

    let mut chunk = vec![0u8; 2048];
    let _response = read_half.read(&mut chunk).await;

    let ct = &chunk[5..5 + 1568];

    let ss = safe_pqc_kyber::decapsulate(ct, &keypair.secret)
        .unwrap()
        .to_vec();
    return ss;
}

pub async fn send_cyphertext(dst_id_bytes: Vec<u8>, cyphertext: Vec<u8>) {
    let keys_lock = crate::GLOBAL_KEYS.lock().await;
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

    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;

    if let Some(tcp_client) = tcp_guard.as_mut() {
        let node_shared_secret = tcp_client.get_node_shared_secret().await;
        let encrypted_packet =
            crate::crypto::utils::encrypt_packet(&raw_packet, &node_shared_secret).await;
        tcp_client.write(&encrypted_packet).await;
    } else {
        println!("No existing TCP client found");
    }
}

pub async fn listen(
    read_half: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    flag: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut chunk = vec![0u8; 1024];
    while !flag.load(Ordering::Relaxed) {
        match timeout(Duration::from_millis(500), read_half.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                println!("Disconnected from server.");
                break;
            }
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);

                if buffer.len() < 3 {
                    println!("[ERROR] Invalid packet: too short");
                    buffer.clear();
                    continue;
                }

                let prefix = buffer[0];
                let payload_size = if prefix == 0xF0 {
                    let payload_size_bytes = &buffer[1..5];
                    u32::from_le_bytes([
                        payload_size_bytes[0],
                        payload_size_bytes[1],
                        payload_size_bytes[2],
                        payload_size_bytes[3],
                    ]) as usize
                } else {
                    let payload_size_bytes = &buffer[1..3];
                    u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize
                };

                if buffer.len() < payload_size {
                    continue;
                }

                match prefix {
                    0x02 => {
                        match crate::network::handle::handle_kyber(&buffer[..payload_size].to_vec())
                            .await
                        {
                            Ok(_) => {}
                            Err(err) => {
                                println!("Error handling kyber: {}", err);
                            }
                        }
                    }
                    0x03 => {
                        if let Err(err) =
                            crate::network::handle::handle_ct(&buffer[..payload_size].to_vec())
                                .await
                        {
                            println!("Error handling ciphertext: {}", err);
                        }
                    }
                    0x04 => {
                        match crate::network::handle::handle_message(
                            &buffer[..payload_size].to_vec(),
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(err) => {
                                println!("Payload size: {}", payload_size);
                                println!("Error handling message: {}", err);
                            }
                        }
                    }
                    0xC0 => {
                        tcp_handles::handle_group_invite(&buffer[..payload_size].to_vec()).await;
                        // PERFECTLY CORRECT
                    }
                    0xC1 => {
                        tcp_handles::handle_group_accept(&buffer[..payload_size].to_vec()).await;
                    }
                    0xC2 => {
                        tcp_handles::handle_hello(&buffer[..payload_size].to_vec()).await;
                    }
                    0xC5 => {
                        tcp_handles::handle_update(&buffer[..payload_size].to_vec()).await;
                    }
                    0xC6 => {
                        // DELETE HANDLE
                    }
                    0xC7 => {
                        // HANDLE MESSAGE
                        tcp_handles::handle_message(&buffer[..payload_size].to_vec()).await;
                    }
                    0xF0 => {
                        let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
                        let app = arc_app.lock().await;
                        let decrypted_packet = match crate::crypto::utils::decrypt_data(
                            &buffer[5 + 32..payload_size].to_vec(),
                            &[0u8; 32].to_vec(),
                        )
                        .await

                        {
                            Ok(decrypted_packet) => decrypted_packet,
                            Err(err) => {
                                println!("[ERROR] Failed to decrypt video packet: {}", err);
                                buffer.advance(payload_size);
                                continue;
                            }
                        };
                        let mut hasher = Hasher::new();
                        hasher.update(&decrypted_packet);
                        let _ = hasher.finalize();
                        app.emit("received-video", &decrypted_packet).unwrap();
                    }
                    _ => {
                        println!("[ERROR] Invalid packet: unknown prefix {}", prefix);
                    }
                }

                buffer.advance(payload_size);
            }
            Ok(Err(e)) => {
                eprintln!("Error reading from stream: {:?}", e);
                break;
            }
            Err(_) => {
                continue;
            }
        }
    }
    Ok(())
}
