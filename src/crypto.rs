use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::rand_core::RngCore;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use rand::Rng;

use crate::errors::AppError;

const NONCE_LEN: usize = 12;

pub struct Vault {
    cipher: Aes256Gcm,
}

impl Vault {
    /// Create a new vault with a master password.
    /// Returns (Vault, salt, verification_ciphertext).
    pub fn create(password: &str) -> Result<(Self, Vec<u8>, Vec<u8>), AppError> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        // Create verification plaintext
        let verification_plaintext = b"twofa-cli-vault-ok";

        let nonce_bytes: [u8; NONCE_LEN] = rand::thread_rng().r#gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let verification_ct = cipher
            .encrypt(nonce, verification_plaintext.as_ref())
            .map_err(|e| AppError::Crypto(format!("Encryption failed: {:?}", e)))?;

        // Prepend nonce to ciphertext for storage
        let mut full = nonce_bytes.to_vec();
        full.extend_from_slice(&verification_ct);

        Ok((Self { cipher }, salt.to_vec(), full))
    }

    /// Unlock an existing vault with a master password.
    pub fn unlock(password: &str, salt: &[u8], verification: &[u8]) -> Result<Self, AppError> {
        if salt.len() < 32 || verification.len() <= NONCE_LEN {
            return Err(AppError::WrongPassword);
        }

        let mut salt_fixed = [0u8; 32];
        salt_fixed.copy_from_slice(&salt[..32]);

        let key = derive_key(password, &salt_fixed)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        // Verify
        let (nonce_bytes, ct) = verification.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ct)
            .map_err(|_| AppError::WrongPassword)?;

        Ok(Self { cipher })
    }

    /// Encrypt a plaintext string. Returns nonce || ciphertext.
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, AppError> {
        let nonce_bytes: [u8; NONCE_LEN] = rand::thread_rng().r#gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| AppError::Crypto(format!("Encryption failed: {:?}", e)))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ct);
        Ok(result)
    }

    /// Decrypt ciphertext (nonce || ciphertext).
    pub fn decrypt(&self, data: &[u8]) -> Result<String, AppError> {
        if data.len() <= NONCE_LEN {
            return Err(AppError::Crypto("Ciphertext too short".into()));
        }
        let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ct)
            .map_err(|_| AppError::Crypto("Decryption failed — wrong key or corrupt data".into()))?;

        String::from_utf8(plaintext)
            .map_err(|e| AppError::Crypto(format!("UTF-8 decode error: {}", e)))
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], AppError> {
    let salt_string =
        SaltString::encode_b64(salt).map_err(|e| AppError::Crypto(format!("Salt: {}", e)))?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| AppError::Crypto(format!("Argon2: {}", e)))?;

    let hash_str = hash.to_string();
    let parsed =
        PasswordHash::new(&hash_str).map_err(|e| AppError::Crypto(format!("Parse: {}", e)))?;

    let raw_hash = parsed
        .hash
        .ok_or_else(|| AppError::Crypto("No hash in output".into()))?;

    let mut key = [0u8; 32];
    let hash_bytes = raw_hash.as_bytes();
    let len = hash_bytes.len().min(32);
    key[..len].copy_from_slice(&hash_bytes[..len]);

    Ok(key)
}
