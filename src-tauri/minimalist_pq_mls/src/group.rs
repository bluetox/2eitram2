use crate::tree::RatchetTree;
use crate::secrets::GroupSecrets;
use serde::{Serialize, Deserialize};

pub const KYBER_PK_SIZE: usize = 1568;
pub const DILITHIUM_PK_SIZE: usize = 1952;
pub const USER_ID_SIZE: usize = 64;
pub const SECRET_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupState {
    pub tree: RatchetTree,
    pub secrets: GroupSecrets,
    pub group_id: String,
    pub epoch: usize,
    pub self_index: usize
}

impl GroupState {
    pub fn new(group_id: &str) -> Self {
        GroupState {
            tree: RatchetTree::new(2),
            secrets: GroupSecrets::new(),
            group_id: group_id.to_string(),
            epoch: 0,
            self_index: 0
        }
    }
    pub fn add_member(
        &mut self,
        kyber_key: Vec<u8>,
        dilithium_key: Vec<u8>,
        ed25519_key: Vec<u8>,
        user_id: &str,
        secret: Vec<u8>,
        index: Option<usize>,
    ) -> (usize , Vec<u8>) {
        if kyber_key.len() != KYBER_PK_SIZE {
            panic!("Kyber public key must be {} bytes, got {}", KYBER_PK_SIZE, kyber_key.len());
        }

        if dilithium_key.len() != DILITHIUM_PK_SIZE {
            panic!("Dilithium public key must be {} bytes, got {}", DILITHIUM_PK_SIZE, dilithium_key.len());
        }

        if user_id.len() != USER_ID_SIZE {
            panic!("User id must be {} bytes, got {}", USER_ID_SIZE, user_id.len());
        }

        if secret.len() != SECRET_SIZE {
            panic!("Secret must be {} bytes, got {}", SECRET_SIZE, secret.len());
        }

        let (index, secrets) = self.tree.add_member(kyber_key, dilithium_key, ed25519_key, user_id, secret, index);
        for (index, node_secret) in &secrets {
            println!("added_node_secret for index: {}", index);
            self.secrets.add_node_secret(index.clone(), node_secret.clone());
        }
        self.secrets.set_root_secret(&secrets.last().unwrap().1);
        self.new_epoch();
        (index, secrets.last().unwrap().1.clone())
    }

    pub fn add_member_from_update(
        &mut self, 
        credentials: crate::Credential,
        secret: Vec<u8>,
        new_index: usize,
        self_index: usize
    ) {

        let keys: Vec<(usize, Vec<u8>)> = self.tree.add_member_from_update(
            credentials.dilithium_pk, 
            credentials.ed25519_pk, 
            credentials.kyber_pk, 
            &credentials.user_id, 
            secret, 
            new_index, 
            self_index
        );

        if let Some((_, root_key)) = keys.iter().find(|(i, _)| *i == 0) {
            self.secrets.set_root_secret(&root_key);
        }
    }
    
    fn new_epoch(&mut self) {
        self.epoch += 1;
    }

    pub fn get_pk(&self, index: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(member) = self.tree.members.get(index) {
            if let Some(m) = member {
                return Some((m.kyber_key.clone(), m.dilithium_key.clone()));
            }
        }
        None
    }

    pub fn index_from_user_id(&self, user_id: &str) -> Option<usize> {
        self.tree.members
            .iter()
            .enumerate()
            .find_map(|(i, m)| m.as_ref().filter(|m| m.user_id == user_id).map(|_| i))
    }    

    pub fn get_root(&self) -> Vec<u8>{
        self.secrets.get_root()
    }
}