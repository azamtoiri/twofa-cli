use std::path::PathBuf;
use std::time::Instant;

use crossterm::event::{self, KeyCode, KeyEventKind};
use ratatui::widgets::ListState;

use crate::crypto::Vault;
use crate::db::Database;
use crate::errors::AppError;
use crate::import::parse_otpauth_uri;
use crate::models::{InputMode, SecretEntry, AppTab, SettingsSubState};

/// Computed display info for each entry
pub struct TotpDisplay {
    pub entry: SecretEntry,
    pub code: String,
    pub ttl: u64,
}

pub struct App {
    pub db: Database,
    pub entries: Vec<SecretEntry>,
    pub list_state: ListState,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub secret_buffer: String,
    pub add_field_index: usize,
    pub search_input: String,
    pub error_message: Option<String>,
    pub notification: Option<(String, Instant)>,
    pub should_quit: bool,
    pub active_tab: AppTab,
    pub change_pwd_old: String,
    pub change_pwd_new: String,
    pub change_pwd_confirm: String,
    pub change_pwd_field_index: usize,
    pub settings_sub_state: SettingsSubState,
    pub settings_menu_index: usize,
}

impl App {
    pub fn new(db: Database, entries: Vec<SecretEntry>) -> Self {
        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            db,
            entries,
            list_state,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            secret_buffer: String::new(),
            add_field_index: 0,
            search_input: String::new(),
            error_message: None,
            notification: None,
            should_quit: false,
            active_tab: AppTab::Keys,
            change_pwd_old: String::new(),
            change_pwd_new: String::new(),
            change_pwd_confirm: String::new(),
            change_pwd_field_index: 0,
            settings_sub_state: SettingsSubState::Menu,
            settings_menu_index: 0,
        }
    }

    /// Generate display info for all entries
    pub fn compute_displays(&self) -> Vec<TotpDisplay> {
        self.entries
            .iter()
            .map(|e| {
                let (code, ttl) = e.generate().unwrap_or_else(|_| ("ERROR".to_string(), 0));
                TotpDisplay {
                    entry: e.clone(),
                    code,
                    ttl,
                }
            })
            .collect()
    }

    /// Filtered entries based on search input
    pub fn filtered_entries(&self) -> Vec<TotpDisplay> {
        let mut displays = self.compute_displays();
        if !self.search_input.is_empty() {
            let q = self.search_input.to_lowercase();
            displays.retain(|d| d.entry.name.to_lowercase().contains(&q));
        }
        displays
    }

    /// Retrieve the currently selected entry from the filtered list, if any
    pub fn selected_entry(&self) -> Option<SecretEntry> {
        let i = self.list_state.selected()?;
        let filtered = self.filtered_entries();
        filtered.get(i).map(|d| d.entry.clone())
    }

    /// Clamps the selected index so it remains valid in the filtered list
    pub fn clamp_selected(&mut self) {
        let len = self.filtered_entries().len();
        if len == 0 {
            self.list_state.select(None);
        } else if let Some(i) = self.list_state.selected() {
            if i >= len {
                self.list_state.select(Some(len.saturating_sub(1)));
            }
        } else {
            self.list_state.select(Some(0));
        }
    }

    /// Handle a key event
    pub fn handle_key(&mut self, key: event::KeyEvent) {
        if key.kind == event::KeyEventKind::Release {
            return;
        }

        if matches!(self.input_mode, InputMode::Notification(_)) {
            self.notification = None;
            self.input_mode = InputMode::Normal;
            return;
        }

        if self.active_tab == AppTab::Settings && matches!(self.input_mode, InputMode::Normal) {
            self.handle_key_settings(key);
            return;
        }

        match self.input_mode.clone() {
            InputMode::Normal => self.handle_key_normal(key),
            InputMode::Search => self.handle_key_search(key),
            InputMode::Adding => self.handle_key_adding(key),
            InputMode::Editing { .. } => self.handle_key_editing(key),
            InputMode::ConfirmDelete { .. } => self.handle_key_confirm(key),
            InputMode::PasswordPrompt { .. } => self.handle_key_password(key),
            InputMode::Notification(_) => {}
        }
    }

    fn handle_key_normal(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('a') => {
                self.input_mode = InputMode::Adding;
                self.input_buffer.clear();
                self.secret_buffer.clear();
                self.add_field_index = 0;
            }
            KeyCode::Char('d') => {
                if let Some(entry) = self.selected_entry() {
                    self.input_mode = InputMode::ConfirmDelete {
                        id: entry.id,
                        name: entry.name.clone(),
                    };
                }
            }
            KeyCode::Char('e') => {
                if let Some(entry) = self.selected_entry() {
                    self.input_mode = InputMode::Editing {
                        id: entry.id,
                        current_name: entry.name.clone(),
                    };
                    self.input_buffer = entry.name.clone();
                }
            }
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Search;
                self.search_input.clear();
                self.clamp_selected();
            }
            KeyCode::Enter => {
                if let Some(entry) = self.selected_entry() {
                    self.copy_code(&entry);
                }
            }
            KeyCode::Char('s') => {
                self.active_tab = AppTab::Settings;
                self.change_pwd_old.clear();
                self.change_pwd_new.clear();
                self.change_pwd_confirm.clear();
                self.change_pwd_field_index = 0;
                self.error_message = None;
                self.settings_sub_state = SettingsSubState::Menu;
                self.settings_menu_index = 0;
            }
            KeyCode::Esc => {
                if !self.search_input.is_empty() {
                    self.search_input.clear();
                    self.clamp_selected();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            _ => {}
        }
    }

    fn handle_key_search(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Enter => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Char(c) => {
                self.search_input.push(c);
                self.clamp_selected();
            }
            KeyCode::Backspace => {
                self.search_input.pop();
                self.clamp_selected();
            }
            _ => {}
        }
    }

    fn handle_key_adding(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.input_buffer.clear();
                self.secret_buffer.clear();
                self.error_message = None;
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                self.add_field_index = 1 - self.add_field_index;
            }
            KeyCode::Enter => {
                self.commit_add();
            }
            KeyCode::Char(c) => {
                self.error_message = None;
                if self.add_field_index == 0 {
                    self.input_buffer.push(c);
                } else {
                    self.secret_buffer.push(c);
                }
            }
            KeyCode::Backspace => {
                self.error_message = None;
                if self.add_field_index == 0 {
                    self.input_buffer.pop();
                } else {
                    self.secret_buffer.pop();
                }
            }
            _ => {}
        }
    }

    fn handle_key_settings(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match self.settings_sub_state {
            SettingsSubState::Menu => {
                match key.code {
                    KeyCode::Esc => {
                        self.active_tab = AppTab::Keys;
                        self.error_message = None;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.settings_menu_index = (self.settings_menu_index + 1) % 2;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.settings_menu_index = (self.settings_menu_index + 1) % 2;
                    }
                    KeyCode::Enter => {
                        if self.settings_menu_index == 0 {
                            self.settings_sub_state = SettingsSubState::ChangePassword;
                            self.change_pwd_old.clear();
                            self.change_pwd_new.clear();
                            self.change_pwd_confirm.clear();
                            self.change_pwd_field_index = 0;
                            self.error_message = None;
                        }
                    }
                    _ => {}
                }
            }
            SettingsSubState::ChangePassword => {
                match key.code {
                    KeyCode::Esc => {
                        self.settings_sub_state = SettingsSubState::Menu;
                        self.change_pwd_old.clear();
                        self.change_pwd_new.clear();
                        self.change_pwd_confirm.clear();
                        self.change_pwd_field_index = 0;
                        self.error_message = None;
                    }
                    KeyCode::Tab => {
                        self.change_pwd_field_index = (self.change_pwd_field_index + 1) % 3;
                    }
                    KeyCode::Down => {
                        self.change_pwd_field_index = (self.change_pwd_field_index + 1) % 3;
                    }
                    KeyCode::Up => {
                        self.change_pwd_field_index = (self.change_pwd_field_index + 2) % 3;
                    }
                    KeyCode::Enter => {
                        self.commit_change_password();
                    }
                    KeyCode::Char(c) => {
                        self.error_message = None;
                        match self.change_pwd_field_index {
                            0 => self.change_pwd_old.push(c),
                            1 => self.change_pwd_new.push(c),
                            2 => self.change_pwd_confirm.push(c),
                            _ => {}
                        }
                    }
                    KeyCode::Backspace => {
                        self.error_message = None;
                        match self.change_pwd_field_index {
                            0 => { self.change_pwd_old.pop(); }
                            1 => { self.change_pwd_new.pop(); }
                            2 => { self.change_pwd_confirm.pop(); }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn commit_change_password(&mut self) {
        let old_pwd = self.change_pwd_old.clone();
        let new_pwd = self.change_pwd_new.clone();
        let confirm_pwd = self.change_pwd_confirm.clone();

        if old_pwd.is_empty() {
            self.error_message = Some("Current password is required".into());
            return;
        }

        if new_pwd.is_empty() {
            self.error_message = Some("New password cannot be empty".into());
            return;
        }

        if new_pwd != confirm_pwd {
            self.error_message = Some("New passwords do not match".into());
            return;
        }

        match self.db.change_master_password(&old_pwd, &new_pwd) {
            Ok(_) => {
                self.change_pwd_old.clear();
                self.change_pwd_new.clear();
                self.change_pwd_confirm.clear();
                self.change_pwd_field_index = 0;
                self.error_message = None;
                self.settings_sub_state = SettingsSubState::Menu;
                self.show_notification("Password changed successfully!");
            }
            Err(e) => {
                self.error_message = Some(format!("Error: {}", e));
            }
        }
    }

    fn handle_key_editing(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.input_buffer.clear();
                self.error_message = None;
            }
            KeyCode::Enter => {
                if let InputMode::Editing { id, .. } = self.input_mode {
                    let new_name = self.input_buffer.trim().to_string();
                    if !new_name.is_empty() {
                        if let Err(e) = self.db.update_name(id, &new_name) {
                            self.error_message = Some(format!("Error: {}", e));
                            return;
                        }
                        self.reload_entries();
                    }
                }
                self.input_mode = InputMode::Normal;
                self.input_buffer.clear();
            }
            KeyCode::Char(c) => {
                self.error_message = None;
                self.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.error_message = None;
                self.input_buffer.pop();
            }
            _ => {}
        }
    }

    fn handle_key_confirm(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let InputMode::ConfirmDelete { id, .. } = self.input_mode {
                    if let Err(e) = self.db.delete_secret(id) {
                        self.error_message = Some(format!("Error: {}", e));
                        self.input_mode = InputMode::Normal;
                        return;
                    }
                    self.reload_entries();
                }
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            _ => {}
        }
    }

    fn handle_key_password(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Enter => {
                // password flow handled externally
            }
            KeyCode::Char(c) => {
                self.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
            }
            _ => {}
        }
    }

    fn commit_add(&mut self) {
        let name = self.input_buffer.trim().to_string();
        let secret_raw = self.secret_buffer.trim().to_string();

        if name.is_empty() {
            self.error_message = Some("Name is required".into());
            return;
        }

        if secret_raw.is_empty() {
            self.error_message = Some("Secret is required".into());
            return;
        }

        let (final_name, final_secret, algo, digits, period) = if secret_raw.starts_with("otpauth://")
        {
            match parse_otpauth_uri(&secret_raw) {
                Ok(uri) => (uri.label, uri.secret_base32, uri.algorithm, uri.digits, uri.period),
                Err(e) => {
                    self.error_message = Some(format!("Invalid URI: {}", e));
                    return;
                }
            }
        } else {
            let clean = secret_raw
                .trim()
                .replace(' ', "")
                .replace('-', "")
                .trim_end_matches('=')
                .to_uppercase();
            match totp_rs::Secret::Encoded(clean.clone()).to_bytes() {
                Ok(_) => (name, clean, "SHA1".into(), 6, 30),
                Err(e) => {
                    self.error_message = Some(format!("Invalid Base32: {}", e));
                    return;
                }
            }
        };

        let temp_entry = SecretEntry {
            id: 0,
            name: final_name.clone(),
            secret_base32: final_secret.clone(),
            algorithm: algo.clone(),
            digits,
            period: period as u64,
            sort_order: 0,
        };
        if let Err(e) = temp_entry.validate() {
            self.error_message = Some(format!("Invalid secret: {}", e));
            return;
        }

        match self.db.add_secret(&final_name, &final_secret, &algo, digits, period as u64) {
            Ok(_) => {
                self.reload_entries();
                self.input_mode = InputMode::Normal;
                self.input_buffer.clear();
                self.secret_buffer.clear();
            }
            Err(e) => {
                self.error_message = Some(format!("Save failed: {}", e));
            }
        }
    }

    fn copy_code(&mut self, entry: &SecretEntry) {
        if let Ok((code, _)) = entry.generate() {
            match arboard::Clipboard::new() {
                Ok(mut clipboard) => {
                    if let Err(e) = clipboard.set_text(code.clone()) {
                        self.show_notification(&format!("Code: {} (clipboard: {})", code, e));
                    } else {
                        self.show_notification(&format!("Copied: {} → {}", entry.name, code));
                    }
                }
                Err(_) => {
                    self.show_notification(&format!("{}: {}", entry.name, code));
                }
            }
        }
    }

    pub fn show_notification(&mut self, msg: &str) {
        self.notification = Some((msg.to_string(), Instant::now()));
        self.input_mode = InputMode::Notification(msg.to_string());
    }

    fn select_next(&mut self) {
        let len = self.filtered_entries().len();
        if len == 0 {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        let next = if i >= len.saturating_sub(1) {
            0
        } else {
            i + 1
        };
        self.list_state.select(Some(next));
    }

    fn select_prev(&mut self) {
        let len = self.filtered_entries().len();
        if len == 0 {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        let prev = if i == 0 {
            len.saturating_sub(1)
        } else {
            i - 1
        };
        self.list_state.select(Some(prev));
    }

    fn reload_entries(&mut self) {
        match self.db.list_secrets() {
            Ok(entries) => {
                self.entries = entries;
                self.clamp_selected();
            }
            Err(e) => {
                self.error_message = Some(format!("DB error: {}", e));
            }
        }
    }
}

/// Password prompt flow — runs before TUI starts.
pub fn password_flow(db_path: &PathBuf) -> Result<(Database, Vec<SecretEntry>), AppError> {
    use std::io::{self, Write};

    let needs_init = if db_path.exists() {
        let conn = rusqlite::Connection::open(db_path)?;
        !Database::is_initialized_raw(&conn)
    } else {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        true
    };

    if needs_init {
        println!("First run — create a master password to encrypt your secrets.");
        print!("Master password: ");
        io::stdout().flush()?;
        let password = read_password_stdin()?;

        print!("Confirm password: ");
        io::stdout().flush()?;
        let confirm = read_password_stdin()?;

        if password != confirm {
            return Err(AppError::General("Passwords do not match".into()));
        }
        if password.is_empty() {
            return Err(AppError::General("Password cannot be empty".into()));
        }

        let (vault, salt, verification) = Vault::create(&password)?;
        let db = Database::open(db_path, vault)?;
        db.save_vault_meta(&salt, &verification)?;
        let entries = db.list_secrets()?;
        Ok((db, entries))
    } else {
        print!("Enter master password: ");
        io::stdout().flush()?;
        let password = read_password_stdin()?;

        let conn = rusqlite::Connection::open(db_path)?;
        if !Database::is_initialized_raw(&conn) {
            return Err(AppError::General("Vault not initialized".into()));
        }

        let salt: Vec<u8> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'salt'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AppError::General("Vault metadata missing".into()))?;

        let verification: Vec<u8> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'verification'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AppError::General("Vault metadata missing".into()))?;

        let vault = Vault::unlock(&password, &salt, &verification)?;
        let db = Database::open(db_path, vault)?;
        let entries = db.list_secrets()?;
        Ok((db, entries))
    }
}

fn read_password_stdin() -> Result<String, AppError> {
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    enable_raw_mode()?;

    let mut password = String::new();
    loop {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == crossterm::event::KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Enter => {
                        break;
                    }
                    KeyCode::Esc => {
                        let _ = disable_raw_mode();
                        println!();
                        return Err(AppError::General("Password entry cancelled".into()));
                    }
                    KeyCode::Backspace => {
                        password.pop();
                    }
                    KeyCode::Char(c) => {
                        password.push(c);
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = disable_raw_mode();
    println!();
    Ok(password)
}
