pub async fn send_group_invite(user_id: &str, group_id: &str, group_name: &str) {
    let mut tcp_guard = crate::GLOBAL_CLIENT.lock().await;
    let tcp_client = tcp_guard.as_mut().unwrap();
    let nss = tcp_client.get_node_shared_secret().await;

    let packet = crate::network::packet::create_group_invite_packet(
        user_id,
        group_id.as_bytes().to_vec(),
        group_name.as_bytes().to_vec(),
        &nss,
    )
    .await
    .unwrap();
    tcp_client.write(&packet).await;
}

pub fn first_divergence_inverted(self_path: &[usize], new_path: &[usize]) -> Option<usize> {
    let len = self_path.len().min(new_path.len());
    for i in 0..len {
        let si = self_path.len() - 1 - i;
        let ni = new_path.len() - 1 - i;
        if self_path[si] != new_path[ni] {
            return Some(self_path[si]);
        }
    }
    None
}
