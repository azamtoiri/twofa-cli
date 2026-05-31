use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Encryption error: {0}")]
    Crypto(String),

    #[error("Invalid secret: {0}")]
    InvalidSecret(String),

    #[error("Master password required")]
    PasswordRequired,

    #[error("Wrong master password")]
    WrongPassword,

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOTP error: {0}")]
    Totp(String),

    #[error("Clipboard error: {0}")]
    Clipboard(String),

    #[error("{0}")]
    General(String),
}
