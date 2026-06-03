use rusqlite::{params, Connection};
use std::path::Path;

use crate::crypto::Vault;
use crate::errors::AppError;
use crate::models::SecretEntry;

pub struct Database {
    conn: Connection,
    vault: Vault,
}

impl Database {
    /// Open or create the database at `db_path`.
    /// Requires an unlocked `Vault`.
    pub fn open(db_path: &Path, vault: Vault) -> Result<Self, AppError> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                secret_encrypted BLOB NOT NULL,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                sort_order INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )?;

        Ok(Self { conn, vault })
    }

    /// Store vault metadata (salt + verification blob).
    pub fn save_vault_meta(&self, salt: &[u8], verification: &[u8]) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('salt', ?1)",
            params![salt],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('verification', ?1)",
            params![verification],
        )?;
        Ok(())
    }

    /// Load vault metadata.
    pub fn load_vault_meta(&self) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let salt: Vec<u8> = self
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'salt'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AppError::General("Vault not initialized".into()))?;

        let verification: Vec<u8> = self
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'verification'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AppError::General("Vault not initialized".into()))?;

        Ok((salt, verification))
    }

    /// Add a new secret. `secret_base32` is encrypted before storage.
    pub fn add_secret(
        &self,
        name: &str,
        secret_base32: &str,
        algorithm: &str,
        digits: usize,
        period: u64,
    ) -> Result<i64, AppError> {
        let encrypted = self.vault.encrypt(secret_base32)?;

        // Get max sort_order
        let max_order: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(sort_order), -1) FROM secrets",
                [],
                |row| row.get(0),
            )?;

        self.conn.execute(
            "INSERT INTO secrets (name, secret_encrypted, algorithm, digits, period, sort_order)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, encrypted, algorithm, digits as i64, period as i64, max_order + 1],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// List all secrets (decrypted) ordered by sort_order.
    pub fn list_secrets(&self) -> Result<Vec<SecretEntry>, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, secret_encrypted, algorithm, digits, period, sort_order
             FROM secrets ORDER BY sort_order",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (id, name, enc, algo, digits, period, sort_order) = row?;
            let secret_base32 = self.vault.decrypt(&enc)?;

            entries.push(SecretEntry {
                id,
                name,
                secret_base32,
                algorithm: algo,
                digits: digits as usize,
                period: period as u64,
                sort_order,
            });
        }

        Ok(entries)
    }

    /// Get a single secret by name or id (as string).
    pub fn get_secret(&self, identifier: &str) -> Result<SecretEntry, AppError> {
        if let Ok(id) = identifier.parse::<i64>() {
            return self.find_by_id(id);
        }
        self.find_by_name(identifier)
    }

    fn find_by_name(&self, name: &str) -> Result<SecretEntry, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, secret_encrypted, algorithm, digits, period, sort_order
             FROM secrets WHERE name = ?1",
        )?;

        let (id, ename, enc, algo, digits, period, sort_order) = stmt
            .query_row(params![name], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|_| AppError::SecretNotFound(name.to_string()))?;

        let secret_base32 = self.vault.decrypt(&enc)?;
        Ok(SecretEntry {
            id,
            name: ename,
            secret_base32,
            algorithm: algo,
            digits: digits as usize,
            period: period as u64,
            sort_order,
        })
    }

    fn find_by_id(&self, id: i64) -> Result<SecretEntry, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, secret_encrypted, algorithm, digits, period, sort_order
             FROM secrets WHERE id = ?1",
        )?;

        let (rid, ename, enc, algo, digits, period, sort_order) = stmt
            .query_row(params![id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|_| AppError::SecretNotFound(id.to_string()))?;

        let secret_base32 = self.vault.decrypt(&enc)?;
        Ok(SecretEntry {
            id: rid,
            name: ename,
            secret_base32,
            algorithm: algo,
            digits: digits as usize,
            period: period as u64,
            sort_order,
        })
    }

    /// Update a secret's name.
    pub fn update_name(&self, id: i64, new_name: &str) -> Result<(), AppError> {
        let affected = self.conn.execute(
            "UPDATE secrets SET name = ?1 WHERE id = ?2",
            params![new_name, id],
        )?;
        if affected == 0 {
            return Err(AppError::SecretNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Delete a secret by id.
    pub fn delete_secret(&self, id: i64) -> Result<(), AppError> {
        let affected = self
            .conn
            .execute("DELETE FROM secrets WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(AppError::SecretNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Change the master password. Decrypts all current secrets and re-encrypts them with the new password.
    /// Verifies the old password first.
    pub fn change_master_password(&mut self, old_password: &str, new_password: &str) -> Result<(), AppError> {
        let (salt, verification) = self.load_vault_meta()?;
        if let Err(_) = Vault::unlock(old_password, &salt, &verification) {
            return Err(AppError::WrongPassword);
        }

        let entries = self.list_secrets()?;
        let (new_vault, new_salt, new_verification) = Vault::create(new_password)?;

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('salt', ?1)",
            params![new_salt],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('verification', ?1)",
            params![new_verification],
        )?;

        for entry in &entries {
            let new_encrypted = new_vault.encrypt(&entry.secret_base32)?;
            tx.execute(
                "UPDATE secrets SET secret_encrypted = ?1 WHERE id = ?2",
                params![new_encrypted, entry.id],
            )?;
        }

        tx.commit()?;
        self.vault = new_vault;

        Ok(())
    }

    /// Check if the database has vault metadata (is initialized).
    pub fn is_initialized_raw(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM vault_meta WHERE key = 'salt'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
            > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Vault;

    #[test]
    fn test_change_master_password() {
        let (vault, salt, verification) = Vault::create("old_password").unwrap();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_twofa_change_pwd.db");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
        }

        let mut db = Database::open(&db_path, vault).unwrap();
        db.save_vault_meta(&salt, &verification).unwrap();

        // Add a secret
        db.add_secret("test_service", "GSLUFLYRJC7ICGON", "SHA1", 6, 30).unwrap();

        // Change master password
        db.change_master_password("old_password", "new_password").unwrap();

        // Verify secrets can still be loaded
        let secrets = db.list_secrets().unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "test_service");
        assert_eq!(secrets[0].secret_base32, "GSLUFLYRJC7ICGON");

        // Unlock with new password
        let (new_salt, new_verification) = db.load_vault_meta().unwrap();
        let unlocked_vault = Vault::unlock("new_password", &new_salt, &new_verification);
        assert!(unlocked_vault.is_ok());

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
    }
}
