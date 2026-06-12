use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, Paragraph},
    Frame,
};

pub mod theme;

use crate::app::App;
use crate::models::InputMode;

/// Main render entry point
pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let side_margin = if area.width < 50 { 0 } else { 2 };
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(side_margin),
            Constraint::Min(20),
            Constraint::Length(side_margin),
        ])
        .split(main_layout[0]);

    let middle_area = content_layout[1];

    match app.active_tab {
        crate::models::AppTab::Keys => {
            render_list(f, middle_area, app);
        }
        crate::models::AppTab::Settings => {
            render_settings(f, middle_area, app);
        }
    }

    render_help(f, main_layout[1], app);

    match &app.input_mode {
        InputMode::Search => render_search(f, area, app),
        InputMode::Adding => render_add_dialog(f, area, app),
        InputMode::Editing { .. } => render_edit_dialog(f, area, app),
        InputMode::ConfirmDelete { .. } => render_confirm_dialog(f, area, app),
        InputMode::PasswordPrompt { .. } => render_password_dialog(f, area, app),
        _ => {}
    }

    // Notification overlay — non-blocking, shown on top of list
    if let Some((msg, _)) = &app.notification {
        render_notification(f, area, msg);
    }
}

fn render_list(f: &mut Frame, area: Rect, app: &mut App) {
    let filtered = app.filtered_entries();
    let total_count = app.entries.len();
    let title = if app.search_input.is_empty() {
        format!(" twofa-cli [{}] ", total_count)
    } else {
        format!(
            " twofa-cli [{}/{}] (filter: \"{}\", Esc to clear) ",
            filtered.len(),
            total_count,
            app.search_input
        )
    };

    let items: Vec<ListItem> = filtered
        .iter()
        .enumerate()
        .map(|(i, display)| {
            let code_color = theme::timer_color(display.ttl, display.entry.period);
            let bar = theme::progress_bar(display.ttl, display.entry.period);
            let timer_style = if display.ttl <= 5 {
                Style::default().fg(theme::COLOR_RED)
            } else {
                Style::default().fg(theme::COLOR_MUTED)
            };

            let name_width = ((area.width as usize).saturating_sub(25)).clamp(10, 24);
            let truncated_name = if display.entry.name.len() > name_width {
                format!("{}…", &display.entry.name[..name_width.saturating_sub(1)])
            } else {
                display.entry.name.clone()
            };

            let is_selected = i == app.list_state.selected().unwrap_or(0);
            let code_bg = if is_selected {
                theme::COLOR_BG
            } else {
                theme::COLOR_SURFACE
            };

            let mut spans = vec![
                Span::styled(
                    format!(" {:<width$} ", truncated_name, width = name_width),
                    Style::default()
                        .fg(theme::COLOR_TEXT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {} ", format_code(&display.code)),
                    Style::default()
                        .bg(code_bg)
                        .fg(code_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {:2}s ", display.ttl), timer_style),
            ];

            if area.width >= 58 {
                spans.push(Span::styled(bar, timer_style));
            }

            let line = Line::from(spans);

            if is_selected {
                ListItem::new(vec![line, Line::from("")]).style(
                    Style::default()
                        .bg(theme::COLOR_SURFACE)
                        .fg(theme::COLOR_PRIMARY),
                )
            } else {
                ListItem::new(vec![line, Line::from("")])
            }
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(title)
                .title_alignment(Alignment::Left)
                .border_style(Style::default().fg(theme::COLOR_MUTED)),
        )
        .highlight_style(
            Style::default()
                .bg(theme::COLOR_SURFACE)
                .fg(theme::COLOR_PRIMARY),
        );

    f.render_stateful_widget(list, area, &mut app.list_state);
}fn render_help(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();
    let width = area.width;

    let add_key = |spans: &mut Vec<Span>, key: &str, desc: &str, compact_desc: &str| {
        let use_desc = if width < 60 { compact_desc } else { desc };
        if use_desc.is_empty() {
            return;
        }
        if !spans.is_empty() {
            spans.push(Span::styled("   ", Style::default().bg(theme::COLOR_SURFACE)));
        }

        spans.push(Span::styled(
            format!(" {} ", key),
            Style::default()
                .bg(theme::COLOR_PRIMARY)
                .fg(theme::COLOR_BG)
                .add_modifier(Modifier::BOLD),
        ));

        spans.push(Span::styled(
            format!(" {} ", use_desc),
            Style::default().fg(theme::COLOR_TEXT).bg(theme::COLOR_SURFACE),
        ));
    };

    match &app.input_mode {
        InputMode::Normal => {
            if app.active_tab == crate::models::AppTab::Settings {
                add_key(&mut spans, "Tab/Arrows", "navigate", "nav");
                add_key(&mut spans, "Enter", "submit", "save");
                add_key(&mut spans, "Esc", "back to keys", "esc");
            } else {
                add_key(&mut spans, "q", "quit", "quit");
                add_key(&mut spans, "a", "add", "add");
                add_key(&mut spans, "Enter", "copy", "copy");
                add_key(&mut spans, "d", "delete", "del");
                add_key(&mut spans, "e", "edit", "edit");
                add_key(&mut spans, "/", "search", "find");
                add_key(&mut spans, "s", "settings", "set");
            }
        }
        InputMode::Search => {
            add_key(&mut spans, "Esc", "cancel", "esc");
            add_key(&mut spans, "Enter", "apply", "ok");
        }
        InputMode::Adding => {
            add_key(&mut spans, "Esc", "cancel", "esc");
            add_key(&mut spans, "Enter", "save", "save");
            add_key(&mut spans, "Tab", "switch", "tab");
        }
        InputMode::Editing { .. } => {
            add_key(&mut spans, "Esc", "cancel", "esc");
            add_key(&mut spans, "Enter", "save", "save");
        }
        InputMode::ConfirmDelete { .. } => {
            add_key(&mut spans, "y", "confirm", "yes");
            add_key(&mut spans, "n", "cancel", "no");
        }
        InputMode::PasswordPrompt { .. } => {
            add_key(&mut spans, "Enter", "submit", "ok");
            add_key(&mut spans, "Esc", "quit", "esc");
        }
        InputMode::Notification(_) => {}
    }

    let help = Paragraph::new(Line::from(spans))
        .alignment(Alignment::Center)
        .style(Style::default().bg(theme::COLOR_SURFACE));
    f.render_widget(help, area);
}

fn render_search(f: &mut Frame, area: Rect, app: &App) {
    let popup_area = centered_rect(60, 3, area);
    f.render_widget(Clear, popup_area);

    let input = Paragraph::new(app.search_input.as_str())
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" Search ")
                .border_style(Style::default().fg(theme::COLOR_PRIMARY)),
        )
        .style(Style::default().fg(theme::COLOR_TEXT));

    f.render_widget(input, popup_area);

    f.set_cursor_position((
        popup_area.x + 1 + (app.search_input.len() as u16).min(popup_area.width.saturating_sub(2)),
        popup_area.y + 1,
    ));
}

fn render_add_dialog(f: &mut Frame, area: Rect, app: &App) {
    let popup_area = centered_rect(65, 10, area);
    f.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .margin(1)
        .split(popup_area);

    let name_style = if app.add_field_index == 0 {
        Style::default().fg(theme::COLOR_ACCENT)
    } else {
        Style::default().fg(theme::COLOR_PRIMARY)
    };

    let secret_style = if app.add_field_index == 1 {
        Style::default().fg(theme::COLOR_ACCENT)
    } else {
        Style::default().fg(theme::COLOR_PRIMARY)
    };

    let name_input = Paragraph::new(app.input_buffer.as_str())
        .block(
            Block::bordered()
                .title(" Name ")
                .border_style(name_style),
        )
        .style(Style::default().fg(theme::COLOR_TEXT));

    let secret_input = Paragraph::new(app.secret_buffer.as_str())
        .block(
            Block::bordered()
                .title(" Secret (Base32 or otpauth:// URI) ")
                .border_style(secret_style),
        )
        .style(Style::default().fg(theme::COLOR_TEXT));

    f.render_widget(name_input, chunks[0]);
    f.render_widget(secret_input, chunks[1]);

    let hint = Paragraph::new("Tab switch field  Enter save  Esc cancel")
        .style(Style::default().fg(theme::COLOR_MUTED))
        .alignment(Alignment::Center);
    f.render_widget(hint, chunks[2]);

    if let Some(ref err) = app.error_message {
        let err_para = Paragraph::new(err.as_str())
            .style(Style::default().fg(theme::COLOR_RED))
            .alignment(Alignment::Center);
        f.render_widget(err_para, chunks[3]);
    }

    if app.add_field_index == 0 {
        f.set_cursor_position((
            chunks[0].x + 1 + (app.input_buffer.len() as u16).min(chunks[0].width.saturating_sub(2)),
            chunks[0].y + 1,
        ));
    } else {
        f.set_cursor_position((
            chunks[1].x + 1 + (app.secret_buffer.len() as u16).min(chunks[1].width.saturating_sub(2)),
            chunks[1].y + 1,
        ));
    }
}

fn render_edit_dialog(f: &mut Frame, area: Rect, app: &App) {
    let popup_area = centered_rect(50, 4, area);
    f.render_widget(Clear, popup_area);

    let input = Paragraph::new(app.input_buffer.as_str())
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" Edit Name ")
                .border_style(Style::default().fg(theme::COLOR_PRIMARY)),
        )
        .style(Style::default().fg(theme::COLOR_TEXT));

    f.render_widget(input, popup_area);

    f.set_cursor_position((
        popup_area.x + 1 + (app.input_buffer.len() as u16).min(popup_area.width.saturating_sub(2)),
        popup_area.y + 1,
    ));
}

fn render_confirm_dialog(f: &mut Frame, area: Rect, app: &App) {
    if let InputMode::ConfirmDelete { name, .. } = &app.input_mode {
        let popup_area = centered_rect(40, 4, area);
        f.render_widget(Clear, popup_area);

        let text = format!("Delete \"{}\"?\n\n[y] Yes  [n] No", name);
        let para = Paragraph::new(text)
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Confirm Delete ")
                    .border_style(Style::default().fg(theme::COLOR_DANGER)),
            )
            .style(Style::default().fg(theme::COLOR_TEXT))
            .alignment(Alignment::Center);

        f.render_widget(para, popup_area);
    }
}

fn render_password_dialog(f: &mut Frame, area: Rect, app: &App) {
    let popup_area = centered_rect(50, 5, area);
    f.render_widget(Clear, popup_area);

    let is_new = matches!(app.input_mode, InputMode::PasswordPrompt { is_new: true });
    let title = if is_new {
        " Create Master Password "
    } else {
        " Enter Master Password "
    };

    let masked: String = "*".repeat(app.input_buffer.len());
    let input = Paragraph::new(masked)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(title)
                .border_style(Style::default().fg(theme::COLOR_ACCENT)),
        )
        .style(Style::default().fg(theme::COLOR_TEXT));

    f.render_widget(input, popup_area);

    if let Some(ref err) = app.error_message {
        let err_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Length(1)])
            .split(popup_area)[1];
        let err_para = Paragraph::new(err.as_str())
            .style(Style::default().fg(theme::COLOR_RED))
            .alignment(Alignment::Center);
        f.render_widget(err_para, err_area);
    }
}

fn render_notification(f: &mut Frame, area: Rect, msg: &str) {
    let popup_area = centered_rect(45, 3, area);
    f.render_widget(Clear, popup_area);

    let para = Paragraph::new(msg)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" Info ")
                .border_style(Style::default().fg(theme::COLOR_ACCENT)),
        )
        .style(Style::default().fg(theme::COLOR_TEXT))
        .alignment(Alignment::Center);

    f.render_widget(para, popup_area);
}



fn render_settings(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(" Settings ")
        .border_style(Style::default().fg(theme::COLOR_MUTED));

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    match app.settings_sub_state {
        crate::models::SettingsSubState::Menu => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Title
                    Constraint::Length(3), // Option 0: Change Password
                    Constraint::Length(3), // Option 1: Keys & Hotkeys
                    Constraint::Length(3), // Option 2: About & Info
                    Constraint::Length(1), // Hint
                    Constraint::Min(0),    // App info/details
                ])
                .margin(1)
                .split(inner_area);

            let title_style = Style::default().fg(theme::COLOR_TEXT).add_modifier(Modifier::BOLD);
            f.render_widget(Paragraph::new("Select settings option:").style(title_style), chunks[0]);

            let opt0_style = if app.settings_menu_index == 0 {
                Style::default().fg(theme::COLOR_PRIMARY).bg(theme::COLOR_SURFACE)
            } else {
                Style::default().fg(theme::COLOR_TEXT)
            };

            let opt1_style = if app.settings_menu_index == 1 {
                Style::default().fg(theme::COLOR_PRIMARY).bg(theme::COLOR_SURFACE)
            } else {
                Style::default().fg(theme::COLOR_TEXT)
            };

            let opt2_style = if app.settings_menu_index == 2 {
                Style::default().fg(theme::COLOR_PRIMARY).bg(theme::COLOR_SURFACE)
            } else {
                Style::default().fg(theme::COLOR_TEXT)
            };

            let opt0_text = if app.settings_menu_index == 0 {
                " ▶  Change Master Password "
            } else {
                "    Change Master Password "
            };

            let opt1_text = if app.settings_menu_index == 1 {
                " ▶  Keys & Hotkeys "
            } else {
                "    Keys & Hotkeys "
            };

            let opt2_text = if app.settings_menu_index == 2 {
                " ▶  About & Info "
            } else {
                "    About & Info "
            };

            let opt0 = Paragraph::new(opt0_text)
                .block(Block::bordered().border_style(opt0_style))
                .style(opt0_style);

            let opt1 = Paragraph::new(opt1_text)
                .block(Block::bordered().border_style(opt1_style))
                .style(opt1_style);

            let opt2 = Paragraph::new(opt2_text)
                .block(Block::bordered().border_style(opt2_style))
                .style(opt2_style);

            f.render_widget(opt0, chunks[1]);
            f.render_widget(opt1, chunks[2]);
            f.render_widget(opt2, chunks[3]);

            let hint = Paragraph::new("Use Up/Down Arrows or j/k to navigate  Enter select  Esc back to Keys list")
                .style(Style::default().fg(theme::COLOR_MUTED))
                .alignment(Alignment::Center);
            f.render_widget(hint, chunks[4]);

            if app.settings_menu_index == 2 {
                let info_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Length(1),
                    ])
                    .split(chunks[5]);

                let app_info = Paragraph::new("twofa-cli v0.1.0 - A sleek terminal TOTP authenticator.")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(theme::COLOR_MUTED));
                let license_info = Paragraph::new("License: MIT. Secure AES-256-GCM database encryption.")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(theme::COLOR_MUTED));
                f.render_widget(app_info, info_chunks[0]);
                f.render_widget(license_info, info_chunks[1]);
            }
        }
        crate::models::SettingsSubState::KeysHelp => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Title
                    Constraint::Min(0),    // Hotkeys list
                    Constraint::Length(1), // Back hint
                ])
                .margin(1)
                .split(inner_area);

            let title_style = Style::default().fg(theme::COLOR_PRIMARY).add_modifier(Modifier::BOLD);
            f.render_widget(Paragraph::new("Keyboard Shortcuts & Hotkeys").style(title_style).alignment(Alignment::Center), chunks[0]);

            let hotkeys_text = vec![
                Line::from(vec![
                    Span::styled(" [ Normal Mode ] ", Style::default().fg(theme::COLOR_ACCENT).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  Enter       ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Copy selected TOTP code to clipboard"),
                ]),
                Line::from(vec![
                    Span::styled("  a           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Add a new 2FA secret (Name and Secret Key)"),
                ]),
                Line::from(vec![
                    Span::styled("  d           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Delete the selected 2FA secret"),
                ]),
                Line::from(vec![
                    Span::styled("  e           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Edit name of the selected 2FA secret"),
                ]),
                Line::from(vec![
                    Span::styled("  /           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Search/filter secrets by name"),
                ]),
                Line::from(vec![
                    Span::styled("  s           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Open Settings menu"),
                ]),
                Line::from(vec![
                    Span::styled("  Esc         ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Clear search filter"),
                ]),
                Line::from(vec![
                    Span::styled("  q           ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Quit the application"),
                ]),
                Line::from(vec![
                    Span::styled("  Up/Down, j/k", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Navigate the list of secrets"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" [ Settings Mode ] ", Style::default().fg(theme::COLOR_ACCENT).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  Up/Down, j/k", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Navigate settings menu"),
                ]),
                Line::from(vec![
                    Span::styled("  Enter       ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Select highlighted settings option"),
                ]),
                Line::from(vec![
                    Span::styled("  Esc         ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Go back to previous menu / main list"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" [ Forms (Add / Edit / Password) ] ", Style::default().fg(theme::COLOR_ACCENT).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  Tab/Arrows  ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Switch between input fields"),
                ]),
                Line::from(vec![
                    Span::styled("  Enter       ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Submit form and save changes"),
                ]),
                Line::from(vec![
                    Span::styled("  Esc         ", Style::default().fg(theme::COLOR_PRIMARY)),
                    Span::raw("Cancel editing and discard changes"),
                ]),
            ];

            let hotkeys_para = Paragraph::new(hotkeys_text)
                .style(Style::default().fg(theme::COLOR_TEXT))
                .block(Block::bordered().border_style(Style::default().fg(theme::COLOR_MUTED)));
            f.render_widget(hotkeys_para, chunks[1]);

            let hint = Paragraph::new("Press Esc to go back to Settings Menu")
                .style(Style::default().fg(theme::COLOR_MUTED))
                .alignment(Alignment::Center);
            f.render_widget(hint, chunks[2]);
        }
        crate::models::SettingsSubState::ChangePassword => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Title
                    Constraint::Length(3), // Old Password
                    Constraint::Length(3), // New Password
                    Constraint::Length(3), // Confirm Password
                    Constraint::Length(1), // Hint
                    Constraint::Min(0),    // Error message
                ])
                .margin(1)
                .split(inner_area);

            let title_style = Style::default().fg(theme::COLOR_TEXT).add_modifier(Modifier::BOLD);
            let title = Paragraph::new("Change Master Password").style(title_style);
            f.render_widget(title, chunks[0]);

            let old_pwd_style = if app.change_pwd_field_index == 0 {
                Style::default().fg(theme::COLOR_ACCENT)
            } else {
                Style::default().fg(theme::COLOR_PRIMARY)
            };

            let new_pwd_style = if app.change_pwd_field_index == 1 {
                Style::default().fg(theme::COLOR_ACCENT)
            } else {
                Style::default().fg(theme::COLOR_PRIMARY)
            };

            let confirm_pwd_style = if app.change_pwd_field_index == 2 {
                Style::default().fg(theme::COLOR_ACCENT)
            } else {
                Style::default().fg(theme::COLOR_PRIMARY)
            };

            let masked_old = "*".repeat(app.change_pwd_old.len());
            let masked_new = "*".repeat(app.change_pwd_new.len());
            let masked_confirm = "*".repeat(app.change_pwd_confirm.len());

            let old_input = Paragraph::new(masked_old)
                .block(Block::bordered().title(" Current Master Password ").border_style(old_pwd_style))
                .style(Style::default().fg(theme::COLOR_TEXT));

            let new_input = Paragraph::new(masked_new)
                .block(Block::bordered().title(" New Master Password ").border_style(new_pwd_style))
                .style(Style::default().fg(theme::COLOR_TEXT));

            let confirm_input = Paragraph::new(masked_confirm)
                .block(Block::bordered().title(" Confirm New Password ").border_style(confirm_pwd_style))
                .style(Style::default().fg(theme::COLOR_TEXT));

            f.render_widget(old_input, chunks[1]);
            f.render_widget(new_input, chunks[2]);
            f.render_widget(confirm_input, chunks[3]);

            let hint = Paragraph::new("Tab/Arrows switch fields  Enter submit  Esc back to Menu")
                .style(Style::default().fg(theme::COLOR_MUTED))
                .alignment(Alignment::Center);
            f.render_widget(hint, chunks[4]);

            if let Some(ref err) = app.error_message {
                let err_para = Paragraph::new(err.as_str())
                    .style(Style::default().fg(theme::COLOR_RED))
                    .alignment(Alignment::Center);
                f.render_widget(err_para, chunks[5]);
            }

            let cursor_y = match app.change_pwd_field_index {
                0 => chunks[1].y + 1,
                1 => chunks[2].y + 1,
                2 => chunks[3].y + 1,
                _ => chunks[1].y + 1,
            };
            let buffer_len = match app.change_pwd_field_index {
                0 => app.change_pwd_old.len(),
                1 => app.change_pwd_new.len(),
                2 => app.change_pwd_confirm.len(),
                _ => 0,
            };
            let active_chunk = match app.change_pwd_field_index {
                0 => chunks[1],
                1 => chunks[2],
                2 => chunks[3],
                _ => chunks[1],
            };
            f.set_cursor_position((
                active_chunk.x + 1 + (buffer_len as u16).min(active_chunk.width.saturating_sub(2)),
                cursor_y,
            ));
        }
    }
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_width = (r.width * percent_x / 100).min(r.width - 4);
    let popup_x = (r.width.saturating_sub(popup_width)) / 2;
    let popup_y = (r.height.saturating_sub(height)) / 2;

    Rect {
        x: r.x + popup_x,
        y: r.y + popup_y,
        width: popup_width,
        height: height.min(r.height),
    }
}

fn format_code(code: &str) -> String {
    code.to_string()
}
