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

        let cleaned = self.secret_base32
            .trim()
            .replace(' ', "")
            .replace('-', "")
            .trim_end_matches('=')
            .to_uppercase();

        let secret = totp_rs::Secret::Encoded(cleaned);
        let bytes = secret
            .to_bytes()
            .map_err(|e| format!("Invalid base32 secret: {}", e))?;

        Ok(TOTP::new_unchecked(algo, self.digits, 1, self.period, bytes))
    }

    /// Generate current code and seconds remaining
    pub fn generate(&self) -> Result<(String, u64), String> {
        let totp = self.to_totp()?;
        let code = totp.generate_current().map_err(|e| format!("{}", e))?;
        let ttl = totp.ttl().map_err(|e| format!("{}", e))?;
        Ok((code, ttl))
    }

    /// Check if the entry has a valid configuration and can generate codes.
    pub fn validate(&self) -> Result<(), String> {
        let totp = self.to_totp()?;
        let _code = totp.generate_current().map_err(|e| format!("Code generation failed: {}", e))?;
        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab {
    Keys,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    CreationDate,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSubState {
    Menu,
    ChangePassword,
    KeysHelp,
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
        current_secret: String,
    },
    ConfirmDelete {
        id: i64,
        name: String,
    },
    PasswordPrompt {
        is_new: bool,
    },
    PasswordPromptForEdit {
        id: i64,
        new_name: String,
        new_secret: String,
    },
    Notification(String),
}

#[cfg(test)]
mod tests {
    use super::SecretEntry;

    #[test]
    fn test_secret_entry_to_totp_normalization() {
        let bad_secrets = vec![
            "gsluflyrjc7icgon",
            "GSLUFLYRJC7ICGON===",
            "GSLU FLYR JC7I CGON",
            "GSLU-FLYR-JC7I-CGON",
            "  gsluflyrjc7icgon  ",
        ];

        for sec in bad_secrets {
            let entry = SecretEntry {
                id: 1,
                name: "test".to_string(),
                secret_base32: sec.to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
                sort_order: 1,
            };
            let totp_res = entry.to_totp();
            assert!(totp_res.is_ok(), "Failed to normalize and convert secret '{}': {:?}", sec, totp_res.err());
        }
    }
}

