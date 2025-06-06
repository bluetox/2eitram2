use serde::{Serialize, Deserialize};
use rand_core::OsRng;
use crate::secrets::{self, GroupSecrets};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Member {
    pub kyber_key: Vec<u8>,
    pub dilithium_key: Vec<u8>,
    pub ed25519_key: Vec<u8>,
    pub user_id: String,
    pub index: usize
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RatchetTree {
    pub members: Vec<Option<Member>>,
    pub nodes: Vec<Option<Node>>,

}

impl RatchetTree {
    pub fn new(initial_size: usize) -> Self {
        let mut members = Vec::with_capacity(initial_size.next_power_of_two());
        members.resize_with(initial_size, || None);
        let mut nodes: Vec<Option<Node>> = Vec::new();
        nodes.push(None);
        RatchetTree { members, nodes: nodes }
    }

    pub fn add_member(
        &mut self,
        group_secret: &mut GroupSecrets,
        kyber_key: Vec<u8>,
        dilithium_key: Vec<u8>,
        ed25519_key: Vec<u8>,
        user_id: &str,
        path_secret: Vec<u8>,
        index: Option<usize>
    ) -> (usize, Vec<(usize, Vec<u8>)>) {
        let next_available_leaf = index.unwrap_or_else(|| {
            self.members.iter()
                .position(|m| m.is_none())
                .unwrap_or(self.members.len())
        });
    
        if next_available_leaf >= self.members.len() {
            let new_size = (self.members.len().max(1)).next_power_of_two() * 2;
            self.members.resize_with(new_size, || None);
            self.grow();

            group_secret.node_secrets = group_secret.node_secrets
                .iter()
                .map(|(index, secret)| (new_index_from_original(*index), secret.clone()))
                .collect();
            println!("tree grew to size: {}", new_size);
        }
    
        if self.members[next_available_leaf].is_some() {
            // Make you have a good reason to overwrite
        }
    
        let member = Member { index: next_available_leaf, kyber_key, dilithium_key, ed25519_key, user_id: user_id.to_owned()};
        self.members[next_available_leaf] = Some(member);
    
 
        let keys = self.update_member_key_with(next_available_leaf, path_secret);
        for (index, node_secret) in &keys {
            group_secret.add_node_secret(index.clone(), node_secret.clone());
        }
        group_secret.set_root_secret(&keys.last().unwrap().1);
        (next_available_leaf, keys)
    }

    pub fn add_member_from_update(
        &mut self, 
        group_secret: &mut GroupSecrets,
        dilithium_key: Vec<u8>,
        ed25519_key: Vec<u8>,
        kyber_key: Vec<u8>,
        user_id: &str,
        secret: Vec<u8>,
        new_index: usize,
        self_index: usize
    ) {
        if new_index >= self.members.len() {
            let new_size = (self.members.len().max(1)).next_power_of_two() * 2;
            self.members.resize_with(new_size, || None);
            self.grow();
            group_secret.node_secrets = group_secret.node_secrets
                .iter()
                .map(|(index, secret)| (new_index_from_original(*index), secret.clone()))
                .collect();
        }
        let mut secret= secret;
        let member = Member {
            index: new_index,
            kyber_key,
            dilithium_key,
            ed25519_key,
            user_id: user_id.to_owned()
        };
        self.members[new_index] = Some(member);
    
        let path_self = self.internal_path_indices(self_index);
        let path_new = self.internal_path_indices(new_index);
        
        if let Some(i) = path_self.iter().position(|n| path_new.contains(n)) {
            let remaining = &path_self[i..];
            println!("remaining: {:?}", remaining);
            println!("SECRET: {:?}", &secret);
            if remaining.len() == 1 {
                group_secret.add_node_secret(0, secret.clone());
                group_secret.set_root_secret(&secret);
                return;
            }
            for &ancestor in &remaining[..remaining.len() - 1] {
                println!("derived");
                secret = crate::crypto::derive_secret(&secret, "node");
                group_secret.add_node_secret(ancestor, secret.clone());
            }
            
        } else {
            println!("No common ancestor found");
        }
        group_secret.set_root_secret(&secret);
    }
    
    pub fn grow(&mut self) {
        use std::mem;

        let old: Vec<Option<Node>> = mem::take(&mut self.nodes);
        let n = old.len();

        let new_size = 2 * n + 1;
        let mut new = Vec::with_capacity(new_size);
        new.resize_with(new_size, || None);

        for (i, node_opt) in old.into_iter().enumerate() {
            let level = ((i + 1) as f64).log2().floor() as usize;
            let shift = 1 << level;
            let new_index = i + shift;
            new[new_index] = node_opt;
        }

        self.nodes = new;
    }
    

    pub fn add_node(&mut self, index: usize, public_key: Vec<u8>) {
        let node = Node {
            public_key: public_key
        };
        self.nodes[index] = Some(node);
    }

    pub fn internal_path_indices(&self, m: usize) -> Vec<usize> {
        let n_members = self.members.len();
        let first_leaf = n_members - 1;
        let mut idx = first_leaf + m;
        let mut path = Vec::new();
        let n_internal = n_members - 1;
        while idx > 0 {
            let p = (idx - 1) / 2;
            if p < n_internal {
                path.push(p);
            }
            idx = p;
        }
        path
    }

    pub fn update_member_key_with(&mut self, index: usize, new_key: Vec<u8>) -> Vec<(usize, Vec<u8>)> {
        let path = self.internal_path_indices(index);
        let mut old_key = new_key;
        let mut keys = Vec::new();
        for i in path {
            old_key = crate::crypto::derive_secret(&old_key, "node");
            keys.push((i, old_key.clone()));
            let keypair = safe_pqc_kyber::keypair(&mut OsRng, Some((&old_key[..32], &old_key[32..])));
            self.add_node(i, keypair.public.to_vec());
        }
        keys
    }

    pub fn print_all_paths(&mut self) {
        for i in 0..self.members.len() {
            let path = self.internal_path_indices(i);
        }
    }

    pub fn get_keys_for_broadcast_new_member_secret(&self, index: usize) -> Vec<(Vec<usize>, usize)> {
        let l = self.members.len();
        let path = self.internal_path_indices(index);
        if path.len() == 1 {
            return Vec::new();
        }

        let mut keys_for_broadcast: Vec<usize> = Vec::new();

        for i in path {
            if i == 0 {
                continue;
            }
            if i % 2 ==  0 {
                keys_for_broadcast.push(i - 1)
            } else {
                keys_for_broadcast.push(i + 1)
            };
        }

        let mut broadcast_plan: Vec<(Vec<usize>, usize)> = Vec::new();
        for i in &keys_for_broadcast {
            broadcast_plan.push((descendant_leaves(*i, l), *i));
        }

        broadcast_plan
    }

    pub fn last_valid_member_index(&self) -> Option<usize> {
        self.members
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| m.is_some())
            .map(|(i, _)| i)
    }
}

pub fn descendant_leaves(i: usize, l: usize) -> Vec<usize> {
    assert!(l.is_power_of_two(), "L must be a power of two");
    assert!(i < l - 1,        "node index must be < L-1");

    let total_levels = l.trailing_zeros() as usize;

    let depth = (usize::BITS as usize - 1 - (i + 1).leading_zeros() as usize) as usize;

    let leaves_per_subtree = 1usize << (total_levels - depth);

    let first_at_depth = (1usize << depth).saturating_sub(1);
    let offset = i - first_at_depth;

    let first_leaf = offset * leaves_per_subtree;

    (first_leaf .. first_leaf + leaves_per_subtree).collect()
}

fn get_used_keypair(updater_path: &[usize], self_path: &[usize]) -> usize {
    let min_len = updater_path.len().min(self_path.len());

    for i in 1..=min_len {
        let up_idx = updater_path.len() - i;
        let self_idx = self_path.len() - i;

        if updater_path[up_idx] != self_path[self_idx] {
            return self_path[self_idx];
        }
    }
    self_path[0]
}

pub fn original_index_from_new(new_index: usize) -> Option<usize> {
    for i in 0..=new_index {
        let level = ((i + 1) as f64).log2().floor() as usize;
        let shift = 1 << level;
        if i + shift == new_index {
            return Some(i);
        }
    }
    None
}

pub fn new_index_from_original(original_index: usize) -> usize {
    let level = ((original_index + 1) as f64).log2().floor() as usize;
    let shift = 1 << level;
    original_index + shift
}