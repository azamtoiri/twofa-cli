use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};

/// Stored secret entry (decrypted at runtime)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: i64,
    pub name: String,
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: usize,
    pub period: u64,
    pub sort_order: i64,
}

impl SecretEntry {
    /// Build a TOTP generator from this entry
    pub fn to_totp(&self) -> Result<TOTP, String> {
        let algo = match self.algorithm.as_str() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            other => return Err(format!("Unknown algorithm: {}", other)),
        };

        let secret = totp_rs::Secret::Encoded(self.secret_base32.clone());
        let bytes = secret
            .to_bytes()
            .map_err(|e| format!("Invalid base32 secret: {}", e))?;

        TOTP::new(algo, self.digits, 1, self.period, bytes)
            .map_err(|e| format!("TOTP init error: {}", e))
    }

    /// Generate current code and seconds remaining
    pub fn generate(&self) -> Result<(String, u64), String> {
        let totp = self.to_totp()?;
        let code = totp.generate_current().map_err(|e| format!("{}", e))?;
        let ttl = totp.ttl().map_err(|e| format!("{}", e))?;
        Ok((code, ttl))
    }
}

/// Parsed result from otpauth:// URI
#[derive(Debug, Clone)]
pub struct OtpAuthUri {
    pub label: String,
    pub issuer: Option<String>,
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: usize,
    pub period: u64,
}

/// App UI mode
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Search,
    Adding,
    Editing {
        id: i64,
        current_name: String,
    },
    ConfirmDelete {
        id: i64,
        name: String,
    },
    PasswordPrompt {
        is_new: bool,
    },
    Notification(String),
}
