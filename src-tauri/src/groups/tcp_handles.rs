use std::str;
use rand::rngs::OsRng;

pub async fn handle_update(
    packet: &Vec<u8>
) {
    let source_id = crate::utils::source_id_from_packet(packet);

    let group_id = str::from_utf8(&packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36]).unwrap();
    let ct = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568];
    let update_enc = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8 + 36 + 1568 ..];

    let mut group = crate::database::group_chat::load_group_from_id(group_id).await.unwrap();

    let updated_index = group.index_from_user_id(&source_id).unwrap();
    let updater_path = group.tree.internal_path_indices(updated_index);
    let self_path = group.tree.internal_path_indices(group.self_index);

    for i in 0..self_path.len() {
        if updater_path[i] == self_path[i] {
            if updater_path.len() == 1 {
                println!("updater node index: {}", updater_path[i]);
                let secret = group.secrets.get_node_secret(updater_path[i]).unwrap();
                let keypair = safe_pqc_kyber::keypair(&mut OsRng, Some((&secret[..32], &secret[32..])));
                let secret = safe_pqc_kyber::decapsulate(ct, &keypair.secret).unwrap();
                let decrypted_update = crate::crypto::utils::decrypt_data(&update_enc.to_vec(), &secret.to_vec()).await.unwrap();
                let update: minimalist_pq_mls::GroupUpdateMember  = bincode::deserialize(&decrypted_update).unwrap();
                group.add_member_from_update(update.new_member_cred, update.key.clone(), update.index, group.self_index);
                for (index, pk) in &update.new_pks {
                    group.tree.add_node(index.clone(), pk.clone());
                }
            } if i == 0 {
                println!("received using perso pk");
                let (sk, pk) = crate::database::group_chat::group_sk_from_group_id(group_id).await.unwrap();
                let secret = safe_pqc_kyber::decapsulate(ct, &sk).unwrap();
                let decrypted_update = crate::crypto::utils::decrypt_data(&update_enc.to_vec(), &secret.to_vec()).await.unwrap();
                let update: minimalist_pq_mls::GroupUpdateMember  = bincode::deserialize(&decrypted_update).unwrap();
                group.add_member_from_update(update.new_member_cred, update.key.clone(), update.index, group.self_index);
                for (index, pk) in &update.new_pks {
                    group.tree.add_node(index.clone(), pk.clone());
                }
            }
            
            else {
                println!("i: {}", i);
                let used_index = self_path[i - 1];
                println!("used node index: {}", used_index);
                let secret = group.secrets.get_node_secret(used_index).unwrap();
                let keypair = safe_pqc_kyber::keypair(&mut OsRng, Some((&secret[..32], &secret[32..])));
                let secret = safe_pqc_kyber::decapsulate(ct, &keypair.secret).unwrap();
                let decrypted_update = crate::crypto::utils::decrypt_data(&update_enc.to_vec(), &secret.to_vec()).await.unwrap();
                let update: minimalist_pq_mls::GroupUpdateMember  = bincode::deserialize(&decrypted_update).unwrap();
                group.add_member_from_update(update.new_member_cred, update.key.clone(), update.index, group.self_index);
                for (index, pk) in &update.new_pks {
                    group.tree.add_node(index.clone(), pk.clone());
                }
            }
        }
    }
    crate::database::group_chat::save_group_state(group, &group_id).await.unwrap();
}