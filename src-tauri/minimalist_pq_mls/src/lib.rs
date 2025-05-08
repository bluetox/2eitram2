pub mod tree;
pub mod group;
pub mod secrets;
pub mod packet;
pub mod crypto;
use std::vec;
use packet::ClientHello;
use sha2::{Digest, Sha256};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Serialize, Deserialize};

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn random_key() -> Vec<u8> {
    let mut rng = OsRng;
    let mut key = vec![0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

pub fn random_in_range(min: usize, max: usize) -> usize {
    OsRng.gen_range(min..max)
}

pub fn encap(kpk: Vec<u8>, secret: &Vec<u8>) -> Vec<u8> {
    safe_pqc_kyber::encrypt(kpk, secret, [0u8; 32]).unwrap()
}

pub fn decap(ksk: Vec<u8>, ct: &Vec<u8>) -> Vec<u8> {
    safe_pqc_kyber::decrypt(ksk, ct).unwrap()
}

pub fn import(data: &[u8]) -> ClientHello {
    bincode::deserialize(data).expect("Failed to deserialize RatchetTree")
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GroupUpdateMember {
    pub new_pks: Vec<(usize, Vec<u8>)>,
    pub new_epoch: usize,
    pub index: usize,
    pub key: Vec<u8>,
    pub new_member_cred: Credential,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Credential {
    pub kyber_pk: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub dilithium_pk: Vec<u8>,
    pub user_id: String
}

