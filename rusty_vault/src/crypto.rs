use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce 
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const CHUNK_SIZE: usize = 4096; // 4KB chunks
const NONCE_SIZE: usize = 12;

pub fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {

    let salt = SaltString::generate(&mut OsRng);//generate random 
    
    // derive 32 from the password + salt
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e))?;
    
    //assume the hash output provides enough entropy for a key.
    let hash = password_hash.hash.unwrap();
    let key_bytes = &hash.as_bytes()[0..32]; // Take first 32 bytes for AES-256
    let cipher = Aes256Gcm::new_from_slice(key_bytes).expect("Invalid key length");

    let mut input_file = File::open(input_path).context("Failed to open input file")?;
    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output_path)
        .context("Failed to create output file")?;

    output_file.write_all(salt.as_str().as_bytes())?; 

    let mut buffer = [0u8; CHUNK_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill(&mut nonce_bytes);
    let mut nonce = Nonce::from_slice(&nonce_bytes).to_owned();
    
    // write initial nonce to file so we know where to start counting
    output_file.write_all(&nonce_bytes)?;

    loop {
        let count = input_file.read(&mut buffer)?;
        if count == 0 { break; } // End of file

        let chunk = &buffer[..count];

        let ciphertext = cipher.encrypt(&nonce, chunk)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
            
        output_file.write_all(&ciphertext)?;
        
        increment_nonce(&mut nonce);
    }

    println!("File encrypted successfully: {}", output_path);
    Ok(())
}

fn increment_nonce(nonce: &mut aes_gcm::Nonce) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
    }
}