#![allow(dead_code)]
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupSecrets {
    pub member_secrets: Vec<(usize,Vec<u8>)>,
    pub node_secrets: Vec<(usize,Vec<u8>)>,
    pub root_secret: Vec<u8>,
}

impl GroupSecrets {
    pub fn new() -> Self {
        GroupSecrets {
            member_secrets: Vec::new(),
            node_secrets: Vec::new(),
            root_secret: Vec::new(),
        }
    }

    pub fn add_member_secret(&mut self, index: usize, secret: Vec<u8>) {
        self.member_secrets.push((index, secret));
    }

    pub fn add_node_secret(&mut self, index: usize, secret: Vec<u8>) {
        if let Some((_, existing_secret)) = self.node_secrets.iter_mut().find(|(idx, _)| *idx == index) {
            *existing_secret = secret;
        } else {
            self.node_secrets.push((index, secret));
        }
    }
    
    pub fn get_node_secret(&self, index: usize) -> Option<&Vec<u8>> {
        self.node_secrets
            .iter()
            .find_map(|(i, secret)| if *i == index { Some(secret) } else { None })
    }

    pub fn get_member_secret(&self, index: usize) -> Option<&Vec<u8>> {
        self.member_secrets.iter().find_map(|(i, secret)| if *i == index { Some(secret) } else { None })
    }

    pub fn set_root_secret(&mut self, secret: &Vec<u8>) {
        println!("ROOT: {:?}", &secret[..4]);
        self.root_secret = secret.clone();
    }
    pub fn get_root(&self) -> Vec<u8> {
        self.root_secret.clone()
    }
}
