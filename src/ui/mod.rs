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

    render_list(f, content_layout[1], app);
    render_help(f, main_layout[1], app);

    match &app.input_mode {
        InputMode::Search => render_search(f, area, app),
        InputMode::Adding => render_add_dialog(f, area, app),
        InputMode::Editing { .. } => render_edit_dialog(f, area, app),
        InputMode::ConfirmDelete { .. } => render_confirm_dialog(f, area, app),
        InputMode::PasswordPrompt { .. } => render_password_dialog(f, area, app),
        InputMode::Notification(msg) => render_notification(f, area, msg),
        _ => {}
    }
}

fn render_list(f: &mut Frame, area: Rect, app: &mut App) {
    let filtered = app.filtered_entries();
    let title = format!(" twofa-cli [{}] ", filtered.len());

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
}

fn render_help(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();
    let width = area.width;

    let add_key = |spans: &mut Vec<Span>, key: &str, desc: &str, compact_desc: &str| {
        let use_desc = if width < 60 { compact_desc } else { desc };
        if use_desc.is_empty() {
            return;
        }
        if !spans.is_empty() {
            let sep = if width < 50 { " " } else if width < 70 { "  " } else { "   " };
            spans.push(Span::styled(sep, Style::default().fg(theme::COLOR_MUTED)));
        }

        spans.push(Span::styled(
            if width < 50 { format!("[{}]", key) } else { format!(" {} ", key) },
            if width < 50 {
                Style::default().fg(theme::COLOR_PRIMARY).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .bg(theme::COLOR_SURFACE)
                    .fg(theme::COLOR_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            }
        ));

        spans.push(Span::styled(
            format!(" {}", use_desc),
            Style::default().fg(theme::COLOR_TEXT),
        ));
    };

    match &app.input_mode {
        InputMode::Normal => {
            add_key(&mut spans, "q", "quit", "quit");
            add_key(&mut spans, "a", "add", "add");
            add_key(&mut spans, "Enter", "copy", "copy");
            add_key(&mut spans, "d", "delete", "del");
            add_key(&mut spans, "e", "edit", "edit");
            add_key(&mut spans, "/", "search", "find");
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
        InputMode::Notification(_) => {
            spans.push(Span::styled(
                if width < 40 { "Press key" } else { "Press any key to dismiss" },
                Style::default()
                    .fg(theme::COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ));
        }
    }

    let help = Paragraph::new(Line::from(spans)).alignment(Alignment::Center);
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
