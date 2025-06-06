use serde::{Serialize, Deserialize};
use crate::tree::RatchetTree;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHello {
    pub index: usize,
    pub path_secret: Vec<u8>,
    pub tree: RatchetTree,
    pub epoch: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewMemberPacket {
    index: usize,
    secret: Vec<u8>,
    public_keys: Vec<Vec<u8>>,
    dilithium_key: Vec<u8>,
    kyber_key: Vec<u8>,
}