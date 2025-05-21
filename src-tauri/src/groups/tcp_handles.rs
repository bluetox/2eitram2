use rand::rngs::OsRng;
use rand::RngCore;
use ring::signature::KeyPair;
use std::str;
use tauri::Emitter;

pub async fn handle_update(packet: &Vec<u8>) {
    let source_id = crate::utils::source_id_from_packet(packet);

    let group_id = str::from_utf8(
        &packet
            [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36],
    )
    .unwrap();
    let ct = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36
        ..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568];
    let update_enc = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568..];

    let mut group = crate::database::group_chat::load_group_from_id(group_id)
        .await
        .unwrap();

    let _updater_index = group.index_from_user_id(&source_id).unwrap();

    let new_member_index = group
        .tree
        .members
        .iter()
        .position(|m| m.is_none())
        .unwrap_or(group.tree.members.len());

    if new_member_index >= group.tree.members.len() {
        let new_size = (group.tree.members.len().max(1)).next_power_of_two() * 2;
        group.tree.members.resize_with(new_size, || None);
        group.tree.grow();
        group.secrets.node_secrets = group
            .secrets
            .node_secrets
            .iter()
            .map(|(index, secret)| {
                (
                    minimalist_pq_mls::tree::new_index_from_original(*index),
                    secret.clone(),
                )
            })
            .collect();
    }

    let self_path = group.tree.internal_path_indices(group.self_index);
    let new_member_path = group.tree.internal_path_indices(new_member_index);

    let broadcast_node = super::utils::first_divergence_inverted(&self_path, &new_member_path);

    if broadcast_node.is_some() {
        let secret = group
            .secrets
            .get_node_secret(broadcast_node.unwrap())
            .unwrap();
        let keypair = safe_pqc_kyber::keypair(&mut OsRng, Some((&secret[..32], &secret[32..])));

        let secret = safe_pqc_kyber::decapsulate(ct, &keypair.secret).unwrap();
        let decrypted_update =
            crate::crypto::utils::decrypt_data(&update_enc.to_vec(), &secret.to_vec())
                .await
                .expect(&format!(
                    "Failed to decrypt update, used secret: {:?} and pk {:?}",
                    &secret,
                    &keypair.public[..4]
                ));
        let update: minimalist_pq_mls::GroupUpdateMember =
            bincode::deserialize(&decrypted_update).unwrap();
        group.add_member_from_update(
            update.new_member_cred,
            update.key.clone(),
            update.index,
            group.self_index,
        );

        for (index, pk) in &update.new_pks {
            group.tree.add_node(index.clone(), pk.clone());
        }
    } else {
        let (sk, pk) = crate::database::group_chat::group_sk_from_group_id(group_id)
            .await
            .unwrap();
        let secret = safe_pqc_kyber::decapsulate(ct, &sk).unwrap();
        let decrypted_update =
            crate::crypto::utils::decrypt_data(&update_enc.to_vec(), &secret.to_vec())
                .await
                .unwrap();
        let update: minimalist_pq_mls::GroupUpdateMember =
            bincode::deserialize(&decrypted_update).unwrap();
        group.add_member(
            update.new_member_cred.kyber_pk,
            update.new_member_cred.dilithium_pk,
            update.new_member_cred.ed25519_pk,
            &update.new_member_cred.user_id,
            update.key.clone(),
            Some(update.index),
        );

        for (index, pk) in &update.new_pks {
            group.tree.add_node(index.clone(), pk.clone());
        }
    }

    crate::database::group_chat::save_group_state(group, &group_id)
        .await
        .unwrap();
}

pub async fn handle_hello(packet: &Vec<u8>) {
    let ct = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36
        ..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568];
    let group_id = str::from_utf8(
        &packet
            [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36],
    )
    .unwrap();
    let client_hello_enc = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568..];

    let (sk, pk) = crate::database::group_chat::group_sk_from_group_id(group_id)
        .await
        .unwrap();

    let key = safe_pqc_kyber::decapsulate(ct, &sk).unwrap();

    let client_hello_bytes =
        crate::crypto::utils::decrypt_data(&client_hello_enc.to_vec(), &key.to_vec())
            .await
            .unwrap();
    let client_hello: minimalist_pq_mls::packet::ClientHello =
        bincode::deserialize(&client_hello_bytes).unwrap();

    let keys_lock = crate::GLOBAL_KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let secrets = minimalist_pq_mls::secrets::GroupSecrets::new();

    let mut new_group = minimalist_pq_mls::group::GroupState {
        tree: client_hello.tree,
        secrets: secrets,
        self_index: client_hello.index,
        group_id: group_id.to_string(),
        epoch: client_hello.epoch,
    };

    new_group.add_member(
        pk,
        keys.dilithium_keys.public.to_vec(),
        keys.ed25519_keys.public_key().as_ref().to_vec(),
        &keys.calculate_user_id(),
        client_hello.path_secret.clone(),
        Some(client_hello.index),
    );

    new_group
        .secrets
        .add_member_secret(client_hello.index.clone(), client_hello.path_secret.clone());
    crate::database::group_chat::save_group_state(new_group, &group_id)
        .await
        .unwrap();
}

pub async fn handle_message(packet: &Vec<u8>) {
    let group_id = str::from_utf8(
        &packet
            [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36],
    )
    .unwrap();
    let message_enc = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36..];

    let group = crate::database::group_chat::load_group_from_id(group_id)
        .await
        .unwrap();

    let secret = &group.get_root()[..32];
    let message_bytes = crate::crypto::utils::decrypt_data(&message_enc.to_vec(), &secret.to_vec())
        .await
        .unwrap();
    let message = str::from_utf8(&message_bytes).unwrap();

    println!("Received message from a group: {}", message);
    let arc_app = crate::GLOBAL_STORE.get().expect("not initialized").clone();
    let app = arc_app.lock().await;
    let source_id = crate::utils::source_id_from_packet(packet);
    let chat_id = crate::database::group_chat::chat_id_from_group_id(&group_id)
        .await
        .unwrap();
    app.emit(
        "received-message",
        format!(
            "{{\"source\": \"{}\", \"message\": \"{}\", \"chatId\": \"{}\"}}",
            source_id, message, chat_id
        ),
    )
    .map_err(|_| "Failed to emit received message to webview")
    .unwrap();
    crate::database::utils::save_message(&chat_id, &source_id, &message, "received")
        .await
        .unwrap();
}

pub async fn handle_group_invite(buffer: &Vec<u8>) {
    let source_id = crate::utils::source_id_from_packet(buffer);
    let group_id = str::from_utf8(
        &buffer
            [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36],
    )
    .unwrap();
    let group_name =
        str::from_utf8(&buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36..]).unwrap();
    let public_key = crate::database::group_chat::save_new_group(group_id, group_name, &source_id)
        .await
        .unwrap();
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;

    if let Some(tcp_client) = tcp_guard.as_mut() {
        let nss = tcp_client.get_node_shared_secret().await;
        let packet = crate::network::packet::create_accept_invite_packet(
            group_id,
            &source_id,
            &nss,
            &public_key,
        )
        .await
        .unwrap();
        tcp_client.write(&packet).await;
    } else {
        println!("No existing TCP client found");
    }
}

pub async fn handle_group_accept(buffer: &Vec<u8>) {
    let group_id = str::from_utf8(
        &buffer
            [5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8..5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36],
    )
    .unwrap();

    let kyber_key = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36..];
    let dilithium_pub_key = &buffer[5 + 3293 + 64..5 + 3293 + 64 + 1952];
    let ed25519_pub_key = &buffer[5 + 3293 + 64 + 1952..5 + 3293 + 64 + 1952 + 32];
    let src_id_nonce = &buffer[5 + 3293 + 64 + 1952 + 32 + 32..5 + 3293 + 64 + 1952 + 32 + 32 + 16];
    let full_hash_input = [
        &dilithium_pub_key[..],
        &ed25519_pub_key[..],
        &src_id_nonce[..],
    ]
    .concat();

    let new_member_uid = crate::utils::create_user_id_hash(&full_hash_input);

    let mut member_ps = [0u8; 32];
    OsRng.fill_bytes(&mut member_ps);

    let mut group = crate::database::group_chat::load_group_from_id(group_id)
        .await
        .unwrap();

    let (new_member_index, _) = group.add_member(
        kyber_key.to_vec(),
        dilithium_pub_key.to_vec(),
        ed25519_pub_key.to_vec(),
        &new_member_uid,
        member_ps.to_vec(),
        None,
    );

    println!("Inserted the new user at index: {}", new_member_index);

    let hello_data = minimalist_pq_mls::packet::ClientHello {
        index: new_member_index,
        path_secret: member_ps.to_vec(),
        epoch: group.epoch,
        tree: group.tree.clone(),
    };

    let hello_data_bytes = bincode::serialize(&hello_data).unwrap();

    crate::network::packet::create_hello_packet(
        &hello_data_bytes,
        &new_member_uid,
        &kyber_key.to_vec(),
        &group_id,
    )
    .await
    .unwrap();

    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
    let tcp_client = tcp_guard.as_mut().unwrap();

    let mut new_member_path = group.tree.internal_path_indices(new_member_index);

    let mut new_pks: Vec<(usize, Vec<u8>)> = Vec::new();
    for index in new_member_path.clone() {
        new_pks.push((
            index,
            group.tree.nodes[index].as_ref().unwrap().public_key.clone(),
        ));
    }

    println!("path: {:?}", new_member_path);

    let mut sent_secret = member_ps.to_vec();
    let mut debug_secret = member_ps.to_vec();
    for i in 0..new_member_path.len() {
        debug_secret = minimalist_pq_mls::crypto::derive_secret(&debug_secret, "node");
        println!("DERIVED {}: {:?}", i, debug_secret);
    }

    sent_secret = minimalist_pq_mls::crypto::derive_secret(&sent_secret, "node");

    for i in &new_member_path {
        sent_secret = minimalist_pq_mls::crypto::derive_secret(&sent_secret, "node");
        if *i == 0 {
            continue;
        }
        if i % 2 == 0 {
            let descendants =
                minimalist_pq_mls::tree::descendant_leaves(i - 1, group.tree.members.len());

            for descendant in descendants {
                if descendant == group.self_index {
                    continue;
                }
                if let Some(member) = group.tree.members[descendant].as_ref() {
                    let group_update = minimalist_pq_mls::GroupUpdateMember {
                        new_epoch: group.epoch,
                        key: sent_secret.clone(),
                        index: new_member_index,
                        new_pks: new_pks.clone(),
                        new_member_cred: minimalist_pq_mls::Credential {
                            kyber_pk: kyber_key.to_vec(),
                            ed25519_pk: ed25519_pub_key.to_vec(),
                            dilithium_pk: dilithium_pub_key.to_vec(),
                            user_id: new_member_uid.clone(),
                        },
                    };
                    println!("sent key: {:?} with index: {}", sent_secret, i - 1);
                    let bin_update = bincode::serialize(&group_update).unwrap();
                    let (ct, secret) = safe_pqc_kyber::encapsulate(
                        &group.tree.nodes[i - 1].as_ref().unwrap().public_key,
                        &mut OsRng,
                        None,
                    )
                    .unwrap();
                    let encrypted_data =
                        crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
                    let raw_packet = crate::network::packet::create_group_update_packet(
                        &member.user_id,
                        &encrypted_data,
                        &ct.to_vec(),
                        &group_id,
                    )
                    .await
                    .unwrap();
                    tcp_client.write_enc(&raw_packet).await;
                }
            }
        } else {
            let descendants =
                minimalist_pq_mls::tree::descendant_leaves(i + 1, group.tree.members.len());

            for descendant in descendants {
                if descendant == group.self_index {
                    continue;
                }
                if let Some(member) = group.tree.members[descendant].as_ref() {
                    let group_update = minimalist_pq_mls::GroupUpdateMember {
                        new_epoch: group.epoch,
                        key: sent_secret.clone(),
                        index: new_member_index,
                        new_pks: new_pks.clone(),
                        new_member_cred: minimalist_pq_mls::Credential {
                            kyber_pk: kyber_key.to_vec(),
                            ed25519_pk: ed25519_pub_key.to_vec(),
                            dilithium_pk: dilithium_pub_key.to_vec(),
                            user_id: new_member_uid.clone(),
                        },
                    };
                    println!("sent key: {:?} with index: {}", sent_secret, i + 1);
                    let bin_update = bincode::serialize(&group_update).unwrap();
                    let (ct, secret) = safe_pqc_kyber::encapsulate(
                        &group.tree.nodes[i + 1].as_ref().unwrap().public_key,
                        &mut OsRng,
                        None,
                    )
                    .unwrap();
                    let encrypted_data =
                        crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
                    let raw_packet = crate::network::packet::create_group_update_packet(
                        &member.user_id,
                        &encrypted_data,
                        &ct.to_vec(),
                        &group_id,
                    )
                    .await
                    .unwrap();
                    tcp_client.write_enc(&raw_packet).await;
                }
            }
        };
    }

    if new_member_index % 2 == 0 {
        if new_member_index + 1 == group.self_index {
        } else if let Some(member) = &group.tree.members[new_member_index + 1] {
            let group_update = minimalist_pq_mls::GroupUpdateMember {
                new_epoch: group.epoch,
                key: member_ps.to_vec(),
                index: new_member_index,
                new_pks: new_pks.clone(),
                new_member_cred: minimalist_pq_mls::Credential {
                    kyber_pk: kyber_key.to_vec(),
                    ed25519_pk: ed25519_pub_key.to_vec(),
                    dilithium_pk: dilithium_pub_key.to_vec(),
                    user_id: new_member_uid.clone(),
                },
            };

            let bin_update = bincode::serialize(&group_update).unwrap();
            let (ct, secret) = safe_pqc_kyber::encapsulate(
                &group.tree.members[new_member_index]
                    .as_ref()
                    .unwrap()
                    .kyber_key,
                &mut OsRng,
                None,
            )
            .unwrap();
            let encrypted_data =
                crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
            let raw_packet = crate::network::packet::create_group_update_packet(
                &member.user_id,
                &encrypted_data,
                &ct.to_vec(),
                &group_id,
            )
            .await
            .unwrap();
            tcp_client.write_enc(&raw_packet).await;
        }
    } else {
        if new_member_index - 1 == group.self_index {
        } else if let Some(member) = &group.tree.members[new_member_index - 1] {
            let group_update = minimalist_pq_mls::GroupUpdateMember {
                new_epoch: group.epoch,
                key: member_ps.to_vec(),
                index: new_member_index,
                new_pks: new_pks.clone(),
                new_member_cred: minimalist_pq_mls::Credential {
                    kyber_pk: kyber_key.to_vec(),
                    ed25519_pk: ed25519_pub_key.to_vec(),
                    dilithium_pk: dilithium_pub_key.to_vec(),
                    user_id: new_member_uid.clone(),
                },
            };
            let bin_update = bincode::serialize(&group_update).unwrap();
            let (ct, secret) = safe_pqc_kyber::encapsulate(
                &group.tree.members[new_member_index - 1]
                    .as_ref()
                    .unwrap()
                    .kyber_key,
                &mut OsRng,
                None,
            )
            .unwrap();
            let encrypted_data =
                crate::crypto::utils::encrypt_data(&bin_update, &secret.to_vec()).await;
            let raw_packet = crate::network::packet::create_group_update_packet(
                &member.user_id,
                &encrypted_data,
                &ct.to_vec(),
                &group_id,
            )
            .await
            .unwrap();
            tcp_client.write_enc(&raw_packet).await;
        }
    }
    crate::database::group_chat::save_group_state(group.clone(), group_id)
        .await
        .unwrap();
}
