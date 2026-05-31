use ratatui::style::Color;

pub const COLOR_BG: Color = Color::Rgb(15, 15, 25);
pub const COLOR_SURFACE: Color = Color::Rgb(25, 25, 40);
pub const COLOR_PRIMARY: Color = Color::Rgb(100, 180, 255);
pub const COLOR_ACCENT: Color = Color::Rgb(0, 230, 180);
pub const COLOR_TEXT: Color = Color::Rgb(220, 220, 240);
pub const COLOR_MUTED: Color = Color::Rgb(120, 120, 150);
pub const COLOR_GREEN: Color = Color::Rgb(80, 220, 100);
pub const COLOR_YELLOW: Color = Color::Rgb(255, 210, 50);
pub const COLOR_RED: Color = Color::Rgb(255, 80, 80);
pub const COLOR_DANGER: Color = Color::Rgb(255, 60, 60);

/// Color for TOTP code based on remaining time
pub fn timer_color(ttl: u64, period: u64) -> Color {
    let pct = ttl as f64 / period as f64;
    if pct > 0.5 {
        COLOR_GREEN
    } else if pct > 0.2 {
        COLOR_YELLOW
    } else {
        COLOR_RED
    }
}

/// Generate a 20-char progress bar string for remaining portion (TTL)
pub fn progress_bar(ttl: u64, period: u64) -> String {
    let width = 20;
    let filled = ((ttl as f64 / period as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    "▓".repeat(filled) + &"░".repeat(empty)
}
