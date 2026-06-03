#![allow(dead_code)]

mod app;
mod crypto;
mod db;
mod errors;
mod import;
mod models;
mod ui;

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::app::{App, password_flow};

/// A sleek TUI 2FA authenticator — manage and generate TOTP codes in your terminal.
#[derive(Parser)]
#[command(name = "twofa")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Print code for a named secret and exit (no TUI)
    #[arg(short, long, value_name = "NAME")]
    secret: Option<String>,

    /// List all stored secrets and exit (no TUI)
    #[arg(short, long)]
    list: bool,

    /// Add a new secret: --add "Name" "BASE32SECRET"
    #[arg(short, long, num_args = 2, value_names = ["NAME", "SECRET"])]
    add: Option<Vec<String>>,

    /// Path to the encrypted database file
    #[arg(long)]
    db: Option<PathBuf>,

    /// Export all secrets in unencrypted JSON format to the specified file path
    #[arg(long, value_name = "PATH")]
    export: Option<PathBuf>,

    /// Import secrets from a decrypted JSON or otpauth:// URI file path
    #[arg(long, value_name = "PATH")]
    import: Option<PathBuf>,
}

fn default_db_path() -> String {
    let home = user_home().unwrap_or_else(|| PathBuf::from("."));
    home.join(".twofa-cli")
        .join("vault.db")
        .to_string_lossy()
        .to_string()
}

fn user_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| {
            std::env::var("USERPROFILE").or_else(|_| {
                let home = std::env::var("HOMEDRIVE").unwrap_or_default()
                    + &std::env::var("HOMEPATH").unwrap_or_default();
                if home.is_empty() {
                    Err(std::env::VarError::NotPresent)
                } else {
                    Ok(home)
                }
            })
        })
        .ok()
        .map(PathBuf::from)
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(|| PathBuf::from(default_db_path()));

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // --- CLI add mode ---
    if let Some(add_args) = cli.add {
        if add_args.len() != 2 {
            anyhow::bail!("Usage: twofa --add <NAME> <BASE32_SECRET>");
        }
        let (db, _) = password_flow(&db_path)?;
        let clean_secret = add_args[1]
            .trim()
            .replace(' ', "")
            .replace('-', "")
            .trim_end_matches('=')
            .to_uppercase();
        
        let temp_entry = crate::models::SecretEntry {
            id: 0,
            name: add_args[0].clone(),
            secret_base32: clean_secret.clone(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            sort_order: 0,
        };
        temp_entry.validate().map_err(|e| anyhow::anyhow!("{}", e))?;

        db.add_secret(&add_args[0], &clean_secret, "SHA1", 6, 30)?;
        println!("Added secret '{}'", add_args[0]);
        return Ok(());
    }

    // --- One-shot: print code for named secret ---
    if let Some(name) = cli.secret {
        let (_, entries) = password_flow(&db_path)?;
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| anyhow::anyhow!("Secret '{}' not found", name))?;
        let (code, ttl) = entry.generate().map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("{} (expires in {}s)", code, ttl);
        return Ok(());
    }

    // --- List mode ---
    if cli.list {
        let (_, entries) = password_flow(&db_path)?;
        if entries.is_empty() {
            println!("No secrets stored.");
            return Ok(());
        }
        println!("{:<30} {:<10} {}", "Name", "Code", "Expires");
        println!("{}", "-".repeat(55));
        for entry in &entries {
            let (code, ttl) = entry.generate().unwrap_or_else(|_| ("ERROR".into(), 0));
            println!("{:<30} {:<10} {}s", entry.name, code, ttl);
        }
        return Ok(());
    }

    // --- Export mode ---
    if let Some(export_path) = cli.export {
        let (_, entries) = password_flow(&db_path)?;
        if entries.is_empty() {
            println!("No secrets to export.");
            return Ok(());
        }
        println!("WARNING: This will export all your 2FA secrets in an UNENCRYPTED JSON format.");
        print!("Are you sure you want to proceed? (y/N): ");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        let trimmed = confirmation.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Export cancelled.");
            return Ok(());
        }

        let json_data = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&export_path, json_data)?;
        println!("Exported {} secrets to {:?}", entries.len(), export_path);
        return Ok(());
    }

    // --- Import mode ---
    if let Some(import_path) = cli.import {
        let (db, _) = password_flow(&db_path)?;
        let content = std::fs::read_to_string(&import_path)?;
        let mut imported = 0;

        // Try parsing as JSON list of SecretEntry first
        if let Ok(entries_to_import) = serde_json::from_str::<Vec<crate::models::SecretEntry>>(&content) {
            for entry in entries_to_import {
                let clean_secret = entry.secret_base32
                    .trim()
                    .replace(' ', "")
                    .replace('-', "")
                    .trim_end_matches('=')
                    .to_uppercase();
                let temp_entry = crate::models::SecretEntry {
                    id: 0,
                    name: entry.name.clone(),
                    secret_base32: clean_secret.clone(),
                    algorithm: entry.algorithm.clone(),
                    digits: entry.digits,
                    period: entry.period,
                    sort_order: 0,
                };
                if let Err(e) = temp_entry.validate() {
                    eprintln!("Warning: Skipping invalid secret '{}': {}", entry.name, e);
                    continue;
                }
                db.add_secret(
                    &entry.name,
                    &clean_secret,
                    &entry.algorithm,
                    entry.digits,
                    entry.period,
                )?;
                imported += 1;
            }
        } else {
            // Fallback to line-by-line parsing: otpauth:// URI or comma-separated Name,Secret
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if trimmed.starts_with("otpauth://") {
                    if let Ok(uri) = crate::import::parse_otpauth_uri(trimmed) {
                        let temp_entry = crate::models::SecretEntry {
                            id: 0,
                            name: uri.label.clone(),
                            secret_base32: uri.secret_base32.clone(),
                            algorithm: uri.algorithm.clone(),
                            digits: uri.digits,
                            period: uri.period,
                            sort_order: 0,
                        };
                        if let Err(e) = temp_entry.validate() {
                            eprintln!("Warning: Skipping invalid URI secret '{}': {}", uri.label, e);
                            continue;
                        }
                        db.add_secret(
                            &uri.label,
                            &uri.secret_base32,
                            &uri.algorithm,
                            uri.digits,
                            uri.period,
                        )?;
                        imported += 1;
                    }
                } else if let Some((name, secret)) = trimmed.split_once(',') {
                    let clean_secret = secret
                        .trim()
                        .replace(' ', "")
                        .replace('-', "")
                        .trim_end_matches('=')
                        .to_uppercase();
                    let temp_entry = crate::models::SecretEntry {
                        id: 0,
                        name: name.trim().to_string(),
                        secret_base32: clean_secret.clone(),
                        algorithm: "SHA1".to_string(),
                        digits: 6,
                        period: 30,
                        sort_order: 0,
                    };
                    if temp_entry.validate().is_ok() {
                        db.add_secret(name.trim(), &clean_secret, "SHA1", 6, 30)?;
                        imported += 1;
                    } else {
                        eprintln!("Warning: Skipping invalid CSV secret '{}'", name.trim());
                    }
                }
            }
        }

        println!("Imported {} secrets from {:?}", imported, import_path);
        return Ok(());
    }

    // --- TUI mode ---
    let (db, entries) = password_flow(&db_path)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(db, entries);

    let tick_rate = std::time::Duration::from_millis(500);
    let res = run_tui(&mut terminal, &mut app, tick_rate);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: std::time::Duration,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| crate::ui::render(f, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }
}
