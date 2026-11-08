use super::theme::Theme;
use crate::app::{ActivePane, App};
use crate::domain::state::ConnectionState;
use crate::ports::pinger::Pinger;
use crate::ports::storage::ConfigStorage;
use crate::ports::vpn_runner::VpnRunner;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Sparkline, Wrap,
};

pub fn render_ui<S: ConfigStorage, R: VpnRunner, P: Pinger>(f: &mut Frame, app: &App<S, R, P>) {
    let theme = Theme::default();
    let area = f.area();

    let header_height = if area.height >= 22 { 5 } else { 3 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height), // Header banner & live telemetry
            Constraint::Min(8),                // Main dashboard
            Constraint::Length(1),             // Footer hotkeys
        ])
        .split(area);

    render_header(f, app, &theme, chunks[0]);
    render_dashboard(f, app, &theme, chunks[1]);
    render_footer(f, app.active_pane, &theme, chunks[2]);
}

fn format_connection_details(
    state: &ConnectionState,
    theme: &Theme,
) -> (&'static str, ratatui::style::Style, String, String) {
    match state {
        ConnectionState::Connected {
            interface,
            assigned_ip,
            connected_at_secs,
        } => {
            let ip_str = format!(
                "[{}] {}",
                interface,
                assigned_ip.as_deref().unwrap_or("No IP")
            );
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(*connected_at_secs);
            let elapsed = now_secs.saturating_sub(*connected_at_secs);
            let hours = elapsed / 3600;
            let mins = (elapsed % 3600) / 60;
            let secs = elapsed % 60;
            let uptime_str = format!("Uptime: {:02}:{:02}:{:02}", hours, mins, secs);
            ("CONNECTED", theme.connected, ip_str, uptime_str)
        }
        ConnectionState::Connecting { .. } => (
            "CONNECTING...",
            theme.connecting,
            String::new(),
            String::new(),
        ),
        ConnectionState::PromptingSudo => (
            "AWAITING SUDO",
            theme.connecting,
            String::new(),
            String::new(),
        ),
        ConnectionState::Authenticating => (
            "AUTHENTICATING...",
            theme.connecting,
            String::new(),
            String::new(),
        ),
        ConnectionState::Disconnecting => (
            "DISCONNECTING...",
            theme.connecting,
            String::new(),
            String::new(),
        ),
        ConnectionState::Failed { error } => ("FAILED", theme.failed, error.clone(), String::new()),
        ConnectionState::Disconnected => (
            "DISCONNECTED",
            theme.disconnected,
            "No active tunnel".to_string(),
            String::new(),
        ),
    }
}

fn render_header<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type)
        .border_style(theme.border)
        .title(" VPN TUI - System Status & Live Telemetry ");

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let (status_badge, status_style, ip_str, uptime_str) =
        format_connection_details(&app.connection_state, theme);

    // Compact fallback if height < 3 or width < 50
    if inner.height < 3 || inner.width < 50 {
        let speed_text = if let Some(stats) = &app.net_stats {
            let (rx, tx) = stats.display_speeds();
            format!("▲ {} | ▼ {}", tx, rx)
        } else {
            "▲ 0 B/s | ▼ 0 B/s".to_string()
        };
        let p = Paragraph::new(Line::from(vec![
            Span::styled(" VPN TUI ", theme.title_active),
            Span::raw(" | Status: "),
            Span::styled(status_badge, status_style),
            Span::raw(" | "),
            Span::styled(speed_text, theme.text),
        ]));
        f.render_widget(p, inner);
        return;
    }

    // Split Layout Option A
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55), // Left: Status, Interface, IP, Uptime, Gateway, Total
            Constraint::Percentage(45), // Right: DL/UL speeds and live Sparklines
        ])
        .split(inner);

    // Left column: 3 rows
    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Row 1: Status + IP + Uptime
            Constraint::Length(1), // Row 2: Gateway endpoint & Active profile
            Constraint::Length(1), // Row 3: Total transfer RX / TX
        ])
        .split(cols[0]);

    let mut row1_spans = vec![
        Span::styled("● ", status_style),
        Span::styled(status_badge, status_style),
    ];
    if !ip_str.is_empty() {
        row1_spans.push(Span::raw("  "));
        row1_spans.push(Span::styled(ip_str, theme.text));
    }
    if !uptime_str.is_empty() {
        row1_spans.push(Span::raw("  "));
        row1_spans.push(Span::styled(uptime_str, theme.footer_desc));
    }
    f.render_widget(Paragraph::new(Line::from(row1_spans)), left_rows[0]);

    let gateway_info = if let Some(prof) = app.selected_profile() {
        format!("Gateway: {} ({})", prof.endpoint, prof.protocol)
    } else {
        "Gateway: (No profile selected)".to_string()
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(gateway_info, theme.text))),
        left_rows[1],
    );

    let total_text = if let Some(stats) = &app.net_stats {
        let total_rx = if stats.rx_bytes >= 1_048_576 {
            format!("{:.1} MB", stats.rx_bytes as f64 / 1_048_576.0)
        } else {
            format!("{} KB", stats.rx_bytes / 1024)
        };
        let total_tx = if stats.tx_bytes >= 1_048_576 {
            format!("{:.1} MB", stats.tx_bytes as f64 / 1_048_576.0)
        } else {
            format!("{} KB", stats.tx_bytes / 1024)
        };
        format!("Total: RX {} | TX {}", total_rx, total_tx)
    } else {
        "Total: RX 0 KB | TX 0 KB".to_string()
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(total_text, theme.footer_desc))),
        left_rows[2],
    );

    // Right column: Dual Sparklines & Speed Rates
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // DL speed + sparkline
            Constraint::Length(1), // UL speed + sparkline
            Constraint::Length(1), // History window label
        ])
        .split(cols[1]);

    let (rx_str, tx_str) = if let Some(stats) = &app.net_stats {
        stats.display_speeds()
    } else {
        ("0 B/s".to_string(), "0 B/s".to_string())
    };

    // DL split: text label on left, sparkline on right
    let dl_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(16), Constraint::Min(8)])
        .split(right_rows[0]);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("▼ DL: ", theme.connected),
            Span::styled(rx_str, theme.text),
        ])),
        dl_chunks[0],
    );
    let rx_spark = Sparkline::default()
        .data(&app.rx_history)
        .style(theme.connected);
    f.render_widget(rx_spark, dl_chunks[1]);

    // UL split: text label on left, sparkline on right
    let ul_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(16), Constraint::Min(8)])
        .split(right_rows[1]);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("▲ UL: ", theme.footer_key),
            Span::styled(tx_str, theme.text),
        ])),
        ul_chunks[0],
    );
    let tx_spark = Sparkline::default()
        .data(&app.tx_history)
        .style(theme.footer_key);
    f.render_widget(tx_spark, ul_chunks[1]);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Telemetry: 30s live window",
            theme.footer_desc,
        ))),
        right_rows[2],
    );
}

fn render_dashboard<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    if app.logs_zoomed {
        render_logs_pane(f, app, theme, area);
        return;
    }
    if app.configs_zoomed {
        render_profiles_list(f, app, theme, area);
        return;
    }

    let main_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(45), // Left: Accounts & Profiles
            Constraint::Percentage(55), // Right: Telemetry & Logs
        ])
        .split(area);

    let left_rows = if app.accounts_expanded {
        let acc_height = (app.accounts.len() as u16 + 2).clamp(5, 10);
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(acc_height), // Accounts (expanded)
                Constraint::Min(6),             // Profiles list
            ])
            .split(main_cols[0])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Accounts (collapsed bar)
                Constraint::Min(6),    // Profiles list
            ])
            .split(main_cols[0])
    };

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Details & Flags (full width)
            Constraint::Min(8),    // Connection Logs (expanded height)
        ])
        .split(main_cols[1]);

    render_accounts_pane(f, app, theme, left_rows[0]);
    render_profiles_list(f, app, theme, left_rows[1]);
    render_details_pane(f, app, theme, right_rows[0]);
    render_logs_pane(f, app, theme, right_rows[1]);
}

pub fn render_accounts_pane<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let is_focused = app.active_pane == ActivePane::Accounts;
    let border_style = if is_focused {
        theme.border_active
    } else {
        theme.border
    };

    if !app.accounts_expanded {
        // Collapsed View (compact 3-line bar)
        let active_info = if let Some(acc) = app.selected_account() {
            let u = acc
                .credentials
                .as_ref()
                .and_then(|c| c.username.as_deref())
                .unwrap_or("no user");
            let ag = acc
                .credentials
                .as_ref()
                .and_then(|c| c.auth_group.as_deref())
                .map(|g| format!(" [{}]", g))
                .unwrap_or_default();
            format!(" Active: {} ({}){}", acc.name, u, ag)
        } else if app.accounts.is_empty() {
            " (No accounts configured. Press [a] to add)".to_string()
        } else {
            " (None selected)".to_string()
        };

        let title = Line::from(vec![
            Span::styled(
                " ▶ Accounts ",
                if is_focused {
                    theme.title_active
                } else {
                    theme.footer_key
                },
            ),
            Span::styled(
                format!("({}) [A: Expand | a: Add] ", app.accounts.len()),
                theme.footer_desc,
            ),
        ]);

        let p = Paragraph::new(Line::from(vec![Span::styled(
            active_info,
            if is_focused {
                theme.highlight
            } else {
                theme.text
            },
        )]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(theme.border_type)
                .border_style(border_style)
                .title(title),
        );
        f.render_widget(p, area);
    } else {
        // Expanded View (Full interactive list)
        let items: Vec<ListItem> = if app.accounts.is_empty() {
            vec![ListItem::new(Line::from(vec![
                Span::styled("  (No accounts configured. Press ", theme.footer_desc),
                Span::styled("[a]", theme.footer_key),
                Span::styled(" to add a new account)", theme.footer_desc),
            ]))]
        } else {
            app.accounts
                .iter()
                .enumerate()
                .map(|(i, acc)| {
                    let is_sel = i == app.selected_account_idx;
                    let marker = if is_sel { "▶ " } else { "  " };
                    let user_info = acc
                        .credentials
                        .as_ref()
                        .and_then(|c| c.username.as_deref())
                        .unwrap_or("no user");
                    let authgroup_info = acc
                        .credentials
                        .as_ref()
                        .and_then(|c| c.auth_group.as_deref())
                        .map(|ag| format!(" [{}]", ag))
                        .unwrap_or_default();
                    let line = Line::from(vec![
                        Span::styled(marker, theme.footer_key),
                        Span::styled(&acc.name, if is_sel { theme.highlight } else { theme.text }),
                        Span::styled(
                            format!(" ({}){}", user_info, authgroup_info),
                            theme.footer_desc,
                        ),
                    ]);
                    ListItem::new(line)
                })
                .collect()
        };

        let title = Line::from(vec![
            Span::styled(" ▼ Accounts ", theme.title_active),
            Span::styled(
                format!(
                    "({}) [A/Space: Collapse | a: Add | e: Edit | x: Del] ",
                    app.accounts.len()
                ),
                theme.footer_desc,
            ),
        ]);

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(theme.border_type)
                .border_style(border_style)
                .title(title),
        );
        let mut state = app.accounts_list_state.clone();
        state.select(Some(app.selected_account_idx));
        f.render_stateful_widget(list, area, &mut state);

        let visible_height = area.height.saturating_sub(2) as usize;
        if app.accounts.len() > visible_height && visible_height > 0 {
            let max_pos = app.accounts.len().saturating_sub(visible_height);
            let pos = app.selected_account_idx.min(max_pos);
            let mut scrollbar_state = ScrollbarState::new(max_pos).position(pos);
            f.render_stateful_widget(
                Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(Some("▲"))
                    .end_symbol(Some("▼")),
                area,
                &mut scrollbar_state,
            );
        }
    }
}

pub fn render_accounts_list<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    render_accounts_pane(f, app, theme, area);
}

fn render_profiles_list<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let is_focused = app.active_pane == ActivePane::Profiles;
    let border_style = if is_focused {
        theme.border_active
    } else {
        theme.border
    };

    let tree = app.visible_tree();
    let items: Vec<ListItem> = if tree.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled("  (No configurations found. Press ", theme.footer_desc),
            Span::styled("[n]", theme.footer_key),
            Span::styled(" to create one, or ", theme.footer_desc),
            Span::styled("[S]", theme.footer_key),
            Span::styled(" to sync)", theme.footer_desc),
        ]))]
    } else {
        tree.iter()
            .enumerate()
            .map(|(i, node)| {
                let is_sel = i == app.selected_tree_idx;
                let marker = if is_sel { "▶ " } else { "  " };

                match node {
                    crate::ui::tree::VisibleTreeNode::Folder {
                        name,
                        depth,
                        expanded,
                        total_profiles,
                        ..
                    } => {
                        let indent = "  ".repeat(*depth);
                        let folder_icon = if *expanded { "▼ " } else { "▶ " };
                        let line = Line::from(vec![
                            Span::styled(marker, theme.footer_key),
                            Span::raw(indent),
                            Span::styled(folder_icon, theme.footer_key),
                            Span::styled(name, if is_sel { theme.highlight } else { theme.text }),
                            Span::styled(format!(" ({})", total_profiles), theme.footer_desc),
                        ]);
                        ListItem::new(line)
                    }
                    crate::ui::tree::VisibleTreeNode::Profile {
                        profile_idx, depth, ..
                    } => {
                        let prof = &app.profiles[*profile_idx];
                        let indent = "  ".repeat(*depth);
                        let proto_badge = match prof.protocol {
                            crate::domain::config::VpnProtocol::OpenConnect => "[OC]",
                            crate::domain::config::VpnProtocol::OpenVpn => "[OV]",
                        };

                        let (latency_badge, latency_style) = match &prof.latency {
                            crate::domain::state::LatencyState::Measured(ms) if *ms < 50 => {
                                (format!("● {}ms", ms), theme.connected)
                            }
                            crate::domain::state::LatencyState::Measured(ms) if *ms <= 120 => {
                                (format!("▲ {}ms", ms), theme.connecting)
                            }
                            crate::domain::state::LatencyState::Measured(ms) => {
                                (format!("■ {}ms", ms), theme.failed)
                            }
                            crate::domain::state::LatencyState::Timeout => {
                                ("✖ T/O".to_string(), theme.failed)
                            }
                            crate::domain::state::LatencyState::Pinging => {
                                ("...".to_string(), theme.connecting)
                            }
                            _ => (prof.latency.display_badge(), theme.footer_desc),
                        };

                        let acc_label = if let Some(acc_id) = &prof.account_id {
                            let name = app
                                .accounts
                                .iter()
                                .find(|a| &a.id == acc_id)
                                .map(|a| a.name.as_str())
                                .unwrap_or(acc_id.0.as_str());
                            format!(" ({})", name)
                        } else if let Some(acc) = app.selected_account() {
                            format!(" ({})", acc.name)
                        } else {
                            String::new()
                        };

                        let line = Line::from(vec![
                            Span::styled(marker, theme.footer_key),
                            Span::raw(indent),
                            Span::styled(proto_badge, theme.footer_key),
                            Span::raw(" "),
                            Span::styled(
                                &prof.name,
                                if is_sel { theme.highlight } else { theme.text },
                            ),
                            Span::styled(acc_label, theme.footer_desc),
                            Span::raw("  "),
                            Span::styled(format!("[{}]", latency_badge), latency_style),
                        ]);
                        ListItem::new(line)
                    }
                }
            })
            .collect()
    };

    let title = if app.configs_zoomed {
        " Configurations [Space: Toggle Folder | Enter: Connect | C/Esc: Restore Split] "
    } else {
        " Configurations [Space: Toggle Folder | Enter: Connect | C: Zoom] "
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(theme.border_type)
            .border_style(border_style)
            .title(title),
    );

    let mut state = app.profiles_list_state.clone();
    state.select(Some(app.selected_tree_idx));
    f.render_stateful_widget(list, area, &mut state);

    let visible_height = area.height.saturating_sub(2) as usize;
    if tree.len() > visible_height && visible_height > 0 {
        let max_pos = tree.len().saturating_sub(visible_height);
        let pos = app.selected_tree_idx.min(max_pos);
        let mut scrollbar_state = ScrollbarState::new(max_pos).position(pos);
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            area,
            &mut scrollbar_state,
        );
    }
}

pub fn render_details_pane<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let is_focused = app.active_pane == ActivePane::Flags;
    let border_style = if is_focused {
        theme.border_active
    } else {
        theme.border
    };

    let details_block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type)
        .border_style(border_style)
        .title(" Configuration Details & Flags ");

    let content = if let Some(prof) = app.selected_profile() {
        let mut lines = Vec::new();

        let acc_name = if let Some(acc_id) = &prof.account_id {
            app.accounts
                .iter()
                .find(|a| &a.id == acc_id)
                .map(|a| a.name.as_str())
                .unwrap_or(acc_id.0.as_str())
        } else if let Some(acc) = app.selected_account() {
            &acc.name
        } else {
            "(None)"
        };

        lines.push(Line::from(vec![
            Span::styled("Name: ", theme.footer_key),
            Span::styled(&prof.name, theme.highlight),
            Span::raw("   |   "),
            Span::styled("Protocol: ", theme.footer_key),
            Span::styled(format!("{}", prof.protocol), theme.text),
            Span::raw("   |   "),
            Span::styled("Account: ", theme.footer_key),
            Span::styled(acc_name, theme.text),
        ]));

        let group_str = prof.group.as_deref().unwrap_or("(Root)");
        lines.push(Line::from(vec![
            Span::styled("Endpoint: ", theme.footer_key),
            Span::styled(&prof.endpoint, theme.text),
            Span::raw("   |   "),
            Span::styled("Folder: ", theme.footer_key),
            Span::styled(group_str, theme.footer_desc),
        ]));

        if let Some(path) = &prof.ovpn_file {
            lines.push(Line::from(vec![
                Span::styled("OVPN Config: ", theme.footer_key),
                Span::styled(path.to_string_lossy().to_string(), theme.footer_desc),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("SSL Policy:  ", theme.footer_key),
                Span::styled(format!("{:?}", prof.ssl_policy), theme.footer_desc),
            ]));
        }

        if prof.flags.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Flags: ", theme.footer_key),
                Span::styled("(No extra flags configured)", theme.footer_desc),
            ]));
        } else {
            let flags_joined = prof.flags.join(" ");
            lines.push(Line::from(vec![
                Span::styled("Flags: ", theme.footer_key),
                Span::styled(flags_joined, theme.text),
            ]));
        }

        lines
    } else {
        vec![Line::styled(
            "Select a profile on the left to inspect details.",
            theme.footer_desc,
        )]
    };

    let p = Paragraph::new(content)
        .block(details_block)
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn render_logs_pane<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let is_focused = app.active_pane == ActivePane::Logs;
    let border_style = if is_focused {
        theme.border_active
    } else {
        theme.border
    };

    let title = if app.logs_zoomed {
        if !app.logs_auto_scroll {
            " Connection Logs [SCROLL PAUSED - G: Resume | f/Esc: Restore Split] "
        } else {
            " Connection Logs [f/Esc: Restore Split] "
        }
    } else if !app.logs_auto_scroll {
        " Connection Logs [SCROLL PAUSED - G: Resume | f: Zoom] "
    } else {
        " Connection Logs [f: Zoom] "
    };

    let visible_height = area.height.saturating_sub(2) as usize;
    let total_logs = app.logs.len();

    let lines: Vec<Line> = if total_logs == 0 {
        vec![Line::styled(
            "Session logs will appear here during connection.",
            theme.footer_desc,
        )]
    } else if total_logs <= visible_height {
        app.logs.iter().map(|l| Line::raw(l.as_str())).collect()
    } else {
        let max_offset = total_logs.saturating_sub(visible_height);
        let effective_offset = app.logs_scroll_offset.min(max_offset);
        let end_idx = total_logs.saturating_sub(effective_offset);
        let start_idx = end_idx.saturating_sub(visible_height);
        app.logs[start_idx..end_idx]
            .iter()
            .map(|l| Line::raw(l.as_str()))
            .collect()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type)
        .border_style(border_style)
        .title(title);

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);

    if total_logs > visible_height && visible_height > 0 {
        let max_pos = total_logs.saturating_sub(visible_height);
        let effective_offset = app.logs_scroll_offset.min(max_pos);
        let pos = max_pos.saturating_sub(effective_offset);
        let mut scrollbar_state = ScrollbarState::new(max_pos).position(pos);
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            area,
            &mut scrollbar_state,
        );
    }
}

fn render_footer(f: &mut Frame, active_pane: ActivePane, theme: &Theme, area: Rect) {
    let spans = match active_pane {
        ActivePane::Accounts => vec![
            Span::styled(" [A/Space]", theme.footer_key),
            Span::styled(" Toggle ", theme.footer_desc),
            Span::styled(" [x]", theme.footer_key),
            Span::styled(" Delete ", theme.footer_desc),
            Span::styled(" [e]", theme.footer_key),
            Span::styled(" Edit ", theme.footer_desc),
            Span::styled(" [a]", theme.footer_key),
            Span::styled(" Add Acc ", theme.footer_desc),
            Span::styled(" [Tab]", theme.footer_key),
            Span::styled(" Switch Pane ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
        ActivePane::Profiles => vec![
            Span::styled(" [Enter]", theme.footer_key),
            Span::styled(" Connect ", theme.footer_desc),
            Span::styled(" [Space]", theme.footer_key),
            Span::styled(" Toggle ", theme.footer_desc),
            Span::styled(" [m]", theme.footer_key),
            Span::styled(" Folder ", theme.footer_desc),
            Span::styled(" [C]", theme.footer_key),
            Span::styled(" Zoom ", theme.footer_desc),
            Span::styled(" [d]", theme.footer_key),
            Span::styled(" Disc ", theme.footer_desc),
            Span::styled(" [A]", theme.footer_key),
            Span::styled(" Accounts ", theme.footer_desc),
            Span::styled(" [n]", theme.footer_key),
            Span::styled(" New Config ", theme.footer_desc),
            Span::styled(" [e]", theme.footer_key),
            Span::styled(" Edit ", theme.footer_desc),
            Span::styled(" [x]", theme.footer_key),
            Span::styled(" Delete ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
        ActivePane::Logs => vec![
            Span::styled(" [j/k]", theme.footer_key),
            Span::styled(" Scroll ", theme.footer_desc),
            Span::styled(" [PgUp/PgDn]", theme.footer_key),
            Span::styled(" Page ", theme.footer_desc),
            Span::styled(" [g/G]", theme.footer_key),
            Span::styled(" Top/Bottom ", theme.footer_desc),
            Span::styled(" [f]", theme.footer_key),
            Span::styled(" Zoom ", theme.footer_desc),
            Span::styled(" [Tab]", theme.footer_key),
            Span::styled(" Switch Pane ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
        _ => vec![
            Span::styled(" [f]", theme.footer_key),
            Span::styled(" Zoom Logs ", theme.footer_desc),
            Span::styled(" [Tab]", theme.footer_key),
            Span::styled(" Switch Pane ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
    };
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::Account;
    use crate::domain::config::Profile;
    use crate::ports::pinger::MockPinger;
    use crate::ports::storage::InMemoryStorage;
    use crate::ports::vpn_runner::MockVpnRunner;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_ui_to_test_backend() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        let acc = Account::new("Corp");
        storage.save_account(&acc).unwrap();

        let prof =
            Profile::new_openconnect("Munich Gateway", "vpn.munich.de:443").with_flag("--no-dtls");
        storage.save_profile(&prof).unwrap();

        let app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        terminal
            .draw(|f| {
                render_ui(f, &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // Verify dashboard title and profile appear in rendered buffer
        assert!(content.contains("VPN TUI"));
        assert!(content.contains("Munich Gateway"));
        assert!(content.contains("Corp"));
        assert!(content.contains("New Config"));
        assert!(content.contains("Edit"));
        assert!(content.contains("Delete"));
        assert!(!content.contains("Import .ovpn"));
    }

    #[test]
    fn test_render_ui_zoomed_logs() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.add_log("Special Zoomed Log Entry");
        app.logs_zoomed = true;

        terminal
            .draw(|f| {
                render_ui(f, &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        assert!(content.contains("Special Zoomed Log Entry"));
        assert!(content.contains("Restore Split"));
        // When zoomed, profiles list is hidden
        assert!(!content.contains("Configurations [Enter: Connect"));
    }

    #[test]
    fn test_render_footer_contextual() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.active_pane = ActivePane::Accounts;

        terminal
            .draw(|f| {
                render_ui(f, &app);
            })
            .unwrap();

        let buffer_acc = format!("{:?}", terminal.backend().buffer());
        assert!(buffer_acc.contains("Add Acc"));
        assert!(buffer_acc.contains("Edit"));
        assert!(buffer_acc.contains("Delete"));

        app.active_pane = ActivePane::Profiles;
        terminal
            .draw(|f| {
                render_ui(f, &app);
            })
            .unwrap();

        let buffer_prof = format!("{:?}", terminal.backend().buffer());
        assert!(buffer_prof.contains("New Config"));
        assert!(buffer_prof.contains("Connect"));
        assert!(buffer_prof.contains("Edit"));
        assert!(buffer_prof.contains("Delete"));
        assert!(buffer_prof.contains("Folder"));
    }

    #[test]
    fn test_render_ui_accounts_collapsed_and_expanded() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        let acc = Account::new("AlphaCorp");
        storage.save_account(&acc).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // 1. Collapsed state
        app.accounts_expanded = false;
        terminal.draw(|f| render_ui(f, &app)).unwrap();
        let content = format!("{:?}", terminal.backend().buffer());
        assert!(content.contains("▶ Accounts"));
        assert!(content.contains("[A: Expand"));
        assert!(content.contains("AlphaCorp"));

        // 2. Expanded state
        app.accounts_expanded = true;
        terminal.draw(|f| render_ui(f, &app)).unwrap();
        let content_exp = format!("{:?}", terminal.backend().buffer());
        assert!(content_exp.contains("▼ Accounts"));
        assert!(content_exp.contains("Collapse"));
        assert!(content_exp.contains("AlphaCorp"));
    }

    #[test]
    fn test_render_ui_zoomed_configs() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        let prof = Profile::new_openconnect("Zurich Node", "vpn.zurich.ch:443")
            .with_group("Europe/Switzerland");
        storage.save_profile(&prof).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.configs_zoomed = true;

        terminal.draw(|f| render_ui(f, &app)).unwrap();

        let content = format!("{:?}", terminal.backend().buffer());
        assert!(content.contains("Zurich Node"));
        assert!(content.contains("Restore Split"));
        // When configs are zoomed, Accounts pane title is hidden
        assert!(!content.contains("Accounts ("));
    }

    #[test]
    fn test_render_header_split_telemetry_connected() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        let prof = Profile::new_openconnect("Frankfurt Hub", "vpn.frankfurt.de:443");
        storage.save_profile(&prof).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.connection_state = ConnectionState::Connected {
            interface: "tun0".to_string(),
            assigned_ip: Some("10.8.0.42".to_string()),
            connected_at_secs: 1000,
        };
        app.update_net_stats(Some(crate::infra::net_monitor::NetStats {
            rx_bytes: 2_500_000,
            tx_bytes: 500_000,
            rx_bytes_per_sec: 120_000.0,
            tx_bytes_per_sec: 45_000.0,
        }));

        terminal.draw(|f| render_ui(f, &app)).unwrap();

        let content = format!("{:?}", terminal.backend().buffer());
        assert!(content.contains("CONNECTED"));
        assert!(content.contains("[tun0] 10.8.0.42"));
        assert!(content.contains("Uptime:"));
        assert!(content.contains("Gateway: vpn.frankfurt.de:443"));
        assert!(content.contains("Total: RX 2.4 MB | TX 488 KB"));
        assert!(content.contains("▼ DL:"));
        assert!(content.contains("▲ UL:"));
        assert!(content.contains("Telemetry: 30s live window"));
    }

    #[test]
    fn test_render_header_compact_fallback() {
        // Height < 22 triggers compact header (height 3)
        let backend = TestBackend::new(100, 20);
        let mut terminal = Terminal::new(backend).unwrap();

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.connection_state = ConnectionState::Disconnected;

        terminal.draw(|f| render_ui(f, &app)).unwrap();

        let content = format!("{:?}", terminal.backend().buffer());
        assert!(content.contains("VPN TUI"));
        assert!(content.contains("Status:"));
        assert!(content.contains("DISCONNECTED"));
        assert!(!content.contains("Telemetry: 30s live window"));
    }

    #[test]
    fn test_render_ui_details_pane_full_width_and_logs() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        let acc = Account::new("AlphaCorp");
        storage.save_account(&acc).unwrap();

        let prof = Profile::new_openconnect("Munich Hub", "vpn.munich.de:443")
            .with_account(acc.id.clone())
            .with_group("Europe/Germany")
            .with_flag("--no-dtls");
        storage.save_profile(&prof).unwrap();

        let app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        terminal.draw(|f| render_ui(f, &app)).unwrap();

        let content = format!("{:?}", terminal.backend().buffer());
        assert!(content.contains("Configuration Details & Flags"));
        assert!(content.contains("Munich Hub"));
        assert!(content.contains("AlphaCorp"));
        assert!(content.contains("Europe/Germany"));
        assert!(content.contains("--no-dtls"));
        assert!(content.contains("Connection Logs"));
    }

    #[test]
    fn test_render_logs_scrolling_and_pause_indicator() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        for i in 1..=40 {
            app.add_log(format!("Log message line {:02}", i));
        }

        // 1. At bottom with auto-scroll active
        terminal.draw(|f| render_ui(f, &app)).unwrap();
        let content_auto = format!("{:?}", terminal.backend().buffer());
        assert!(content_auto.contains("Log message line 40"));
        assert!(!content_auto.contains("SCROLL PAUSED"));

        // 2. Scrolled up, auto-scroll paused
        app.scroll_logs_up(15);
        terminal.draw(|f| render_ui(f, &app)).unwrap();
        let content_paused = format!("{:?}", terminal.backend().buffer());
        assert!(content_paused.contains("SCROLL PAUSED - G: Resume"));
        assert!(content_paused.contains("Log message line 25"));

        // 3. Zoomed view preserves pause indicator
        app.logs_zoomed = true;
        terminal.draw(|f| render_ui(f, &app)).unwrap();
        let content_zoomed = format!("{:?}", terminal.backend().buffer());
        assert!(content_zoomed.contains("SCROLL PAUSED - G: Resume | f/Esc: Restore Split"));
    }

    #[test]
    fn test_render_profiles_and_accounts_scrollbar() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut storage = InMemoryStorage::new();
        for i in 1..=25 {
            let prof =
                Profile::new_openconnect(format!("Node {:02}", i), format!("10.0.0.{}:443", i));
            storage.save_profile(&prof).unwrap();
        }
        for i in 1..=12 {
            let acc = Account::new(format!("Acc {:02}", i));
            storage.save_account(&acc).unwrap();
        }

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.accounts_expanded = true;

        terminal.draw(|f| render_ui(f, &app)).unwrap();

        let content = format!("{:?}", terminal.backend().buffer());
        // Scrollbar up/down arrows appear
        assert!(content.contains("▲"));
        assert!(content.contains("▼"));
    }
}
