use bytes::{Buf, BytesMut};
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub async fn establish_ss_with_node(read_half: &mut tokio::io::ReadHalf<TcpStream>, write_half:  &mut tokio::io::WriteHalf<TcpStream>) -> Vec<u8> {
    let mut message = BytesMut::with_capacity(1573);
    let total_size =  1573 as u16;
    let mut rng =   rand::rngs::OsRng;
    let keypair = safe_pqc_kyber::Keypair::generate(&mut rng);

    message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    message[1..3].copy_from_slice(&total_size.to_le_bytes());
    message.extend_from_slice(&keypair.public);

    let _ = write_half.write_all(&message).await;

    let mut chunk = vec![0u8; 2048];
    let _response = read_half.read(&mut chunk).await;

    let ct = &chunk[5 .. 5 + 1568];

    let ss = safe_pqc_kyber::decapsulate(ct, &keypair.secret).unwrap().to_vec();
    return ss;
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

    let client = super::super::TCP_CLIENT.lock().await;
    let node_shared_secret = client.get_node_shared_secret().await;
    let encrypted_packet = crate::encryption::utils::encrypt_packet(&raw_packet, &node_shared_secret).await;
    drop(client);

    return encrypted_packet;
}

pub async fn listen(
    read_half: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    app: &AppHandle,
    flag: Arc<AtomicBool>
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut chunk = vec![0u8; 1024];
    while !flag.load(Ordering::Relaxed) {
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
                        let response = crate::modules::handle::handle_kyber(&buffer[..payload_size].to_vec()).await.unwrap();
                        {
                            let mut client = super::super::TCP_CLIENT.lock().await;
                            client.write(&response).await;
                        }
                    }
                    3 => {
                        if let Err(err) = crate::modules::handle::handle_ct(&buffer[..payload_size].to_vec()).await {
                            println!("Error handling ciphertext: {}", err);
                        }                        
                    }
                    4 => {
                        let _ = crate::modules::handle::handle_message(&buffer[..payload_size].to_vec(), app).await;
                    }

                    176 => {
                        //let packet = &buffer[..payload_size];
                        //let pk = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568];
                        //let rest = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 1568..];
                        //let parts: Vec<&[u8]> = rest.split(|b| *b == b'\n').collect();
                        //let name =  String::from_utf8(parts[0].to_vec()).unwrap();
                        //let group_id = String::from_utf8(parts[1].to_vec()).unwrap();
                        //let dilihium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
                        //let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
                        //let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
                        //let full_hash_input = [
                        //    &dilihium_pub_key[..],
                        //    &ed25519_public_key[..],
                        //    &src_id_nonce[..],
                        //]
                        //.concat();
                        //let owner = crate::modules::utils::create_user_id_hash(&full_hash_input);
                        //crate::modules::database::add_group(&name, &group_id, &owner).await.unwrap();
                        //let mut rng =   rand::rngs::OsRng;
                        //let (ciphertext, shared_secret) = safe_pqc_kyber::encapsulate(&pk, &mut rng).unwrap();  
                        
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

