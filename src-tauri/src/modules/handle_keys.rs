use sqlx::Row;

pub async fn load_keys(password: &str) -> Result<super::objects::Keys, String> {

    let current_profile = super::utils::get_profile_name().await;
    let db = super::super::GLOBAL_DB
    .get()
    .ok_or_else(|| "Database not initialized".to_string())?;

    let row = sqlx::query(
        "SELECT dilithium_public, dilithium_private, kyber_public, kyber_private, ed25519, nonce, user_id, password_hash 
         FROM profiles 
         WHERE profile_name = ?"
    )
    .bind(current_profile)
    .fetch_one(db)
    .await
    .map_err(|e| format!("Error fetching profile data: {}", e))?;

    let mut key = super::super::ENCRYPTION_KEY.lock().await;
    *key = generate_pbkdf2_key(password);

    let dilithium_public: Vec<u8> = super::encryption::decrypt_data(&row.get("dilithium_public"), &key).await?;
    let dilithium_private: Vec<u8> = super::encryption::decrypt_data(&row.get("dilithium_private"), &key).await?;
    let kyber_public: Vec<u8> = super::encryption::decrypt_data(&row.get("kyber_public"), &key).await?;
    let kyber_private: Vec<u8> = super::encryption::decrypt_data(&row.get("kyber_private"), &key).await?;
    let ed25519: Vec<u8> = super::encryption::decrypt_data(&row.get("ed25519"), &key).await?;
    let nonce: Vec<u8> = super::encryption::decrypt_data(&row.get("nonce"), &key).await?;
    let _user_id: String = row.get("user_id");
    let password_hash: String = row.get("password_hash");
    
    let mut d_public_key_array = [0u8; 1952];
    let mut d_private_key_array = [0u8; 4000];
    let mut nonce_array = [0u8; 16];
    let mut k_public_key_array = [0u8; 1568];
    let mut k_private_key_array = [0u8; 3168];

    d_public_key_array.copy_from_slice(&dilithium_public);
    d_private_key_array.copy_from_slice(&dilithium_private);
    nonce_array.copy_from_slice(&nonce);
    k_public_key_array.copy_from_slice(&kyber_public);
    k_private_key_array.copy_from_slice(&kyber_private);

    let dilithium_keypair = pqc_dilithium::Keypair::load(d_public_key_array, d_private_key_array);
    let ed25519: ring::signature::Ed25519KeyPair = ring::signature::Ed25519KeyPair::from_pkcs8(&ed25519).map_err(|e| e.to_string())?;
    let kyber_keys = pqc_kyber::Keypair {
        public: k_public_key_array,
        secret: k_private_key_array,
    };

    let is_valid = bcrypt::verify(password, &password_hash).expect("Failed to verify password");
    if is_valid {
        println!("Password is valid!");
    } else {
        println!("Invalid password!");
    }
    let keys = super::objects::Keys {
        ed25519_keys: ed25519,
        dilithium_keys: dilithium_keypair,
        kyber_keys,
        nonce: nonce_array,
    };
    Ok(keys)
}

pub fn generate_pbkdf2_key(password: &str) -> Vec<u8>{
    let iterations = std::num::NonZeroU32::new(100_000).unwrap().get();

    const FIXED_SALT: &[u8] = b"this is my fixed salt!";

    let mut pbkdf2_key = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&password.as_bytes(), &FIXED_SALT, iterations, &mut pbkdf2_key).unwrap();
    pbkdf2_key.to_vec()
}