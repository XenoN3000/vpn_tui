use super::theme::Theme;
use crate::app::{ActivePane, App};
use crate::domain::state::ConnectionState;
use crate::ports::pinger::Pinger;
use crate::ports::storage::ConfigStorage;
use crate::ports::vpn_runner::VpnRunner;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub fn render_ui<S: ConfigStorage, R: VpnRunner, P: Pinger>(f: &mut Frame, app: &App<S, R, P>) {
    let theme = Theme::default();
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header banner
            Constraint::Min(10),   // Main dashboard
            Constraint::Length(1), // Footer hotkeys
        ])
        .split(area);

    render_header(f, app, &theme, chunks[0]);
    render_dashboard(f, app, &theme, chunks[1]);
    render_footer(f, app.active_pane, &theme, chunks[2]);
}

fn render_header<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let (status_text, status_style) = match &app.connection_state {
        ConnectionState::Connected {
            interface,
            assigned_ip,
            ..
        } => {
            let ip_str = assigned_ip.as_deref().unwrap_or("No IP");
            (
                format!("● CONNECTED [{}] IP: {}", interface, ip_str),
                theme.connected,
            )
        }
        ConnectionState::Connecting { .. } => ("○ CONNECTING...".to_string(), theme.connecting),
        ConnectionState::PromptingSudo => ("? AWAITING SUDO AUTH".to_string(), theme.connecting),
        ConnectionState::Authenticating => ("○ AUTHENTICATING...".to_string(), theme.connecting),
        ConnectionState::Disconnecting => ("○ DISCONNECTING...".to_string(), theme.connecting),
        ConnectionState::Failed { error } => (format!("× FAILED: {}", error), theme.failed),
        ConnectionState::Disconnected => ("○ DISCONNECTED".to_string(), theme.disconnected),
    };

    let speed_text = if let Some(stats) = &app.net_stats {
        let (rx, tx) = stats.display_speeds();
        format!("▲ {} | ▼ {}", tx, rx)
    } else {
        "▲ 0 B/s | ▼ 0 B/s".to_string()
    };

    let title_line = Line::from(vec![
        Span::styled(" VPN TUI ", theme.title_active),
        Span::raw(" | Status: "),
        Span::styled(status_text, status_style),
        Span::raw(" | "),
        Span::styled(speed_text, theme.text),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border)
        .title(" System Status ");

    let p = Paragraph::new(title_line).block(block);
    f.render_widget(p, area);
}

fn render_dashboard<S: ConfigStorage, R: VpnRunner, P: Pinger>(
    f: &mut Frame,
    app: &App<S, R, P>,
    theme: &Theme,
    area: Rect,
) {
    let main_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Left column (Accounts & Profiles)
            Constraint::Percentage(60), // Right column (Details/Flags & Logs)
        ])
        .split(area);

    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Accounts
            Constraint::Percentage(60), // Profiles
        ])
        .split(main_cols[0]);

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // Details / Flags
            Constraint::Percentage(55), // Logs
        ])
        .split(main_cols[1]);

    render_accounts_list(f, app, theme, left_rows[0]);
    render_profiles_list(f, app, theme, left_rows[1]);
    render_profile_details(f, app, theme, right_rows[0]);
    render_logs_pane(f, app, theme, right_rows[1]);
}

fn render_accounts_list<S: ConfigStorage, R: VpnRunner, P: Pinger>(
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

    let items: Vec<ListItem> = app
        .accounts
        .iter()
        .enumerate()
        .map(|(i, acc)| {
            let is_sel = i == app.selected_account_idx;
            let marker = if is_sel { ">" } else { " " };
            let user_info = acc
                .credentials
                .as_ref()
                .and_then(|c| c.username.as_deref())
                .unwrap_or("no user");
            let line = Line::from(vec![
                Span::raw(format!("{} ", marker)),
                Span::styled(&acc.name, if is_sel { theme.highlight } else { theme.text }),
                Span::styled(format!(" ({})", user_info), theme.footer_desc),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Accounts [a: Add] "),
    );
    f.render_widget(list, area);
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

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, prof)| {
            let is_sel = i == app.selected_profile_idx;
            let marker = if is_sel { "▶" } else { " " };
            let proto_badge = match prof.protocol {
                crate::domain::config::VpnProtocol::OpenConnect => "[OC]",
                crate::domain::config::VpnProtocol::OpenVpn => "[OV]",
            };
            let latency_badge = prof.latency.display_badge();

            let line = Line::from(vec![
                Span::raw(format!("{} ", marker)),
                Span::styled(proto_badge, theme.footer_key),
                Span::raw(" "),
                Span::styled(
                    &prof.name,
                    if is_sel { theme.highlight } else { theme.text },
                ),
                Span::raw("  "),
                Span::styled(format!("[{}]", latency_badge), theme.footer_desc),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Configurations [Enter: Connect | p: Ping All] "),
    );
    f.render_widget(list, area);
}

fn render_profile_details<S: ConfigStorage, R: VpnRunner, P: Pinger>(
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

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Configuration Details & Flags ");

    let content = if let Some(prof) = app.selected_profile() {
        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("Name:     ", theme.footer_key),
            Span::raw(&prof.name),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Protocol: ", theme.footer_key),
            Span::raw(format!("{}", prof.protocol)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Endpoint: ", theme.footer_key),
            Span::raw(&prof.endpoint),
        ]));
        if let Some(path) = &prof.ovpn_file {
            lines.push(Line::from(vec![
                Span::styled("OVPN:     ", theme.footer_key),
                Span::raw(path.to_string_lossy().to_string()),
            ]));
        }

        lines.push(Line::raw(""));
        lines.push(Line::styled("Active Flags:", theme.footer_key));
        if prof.flags.is_empty() {
            lines.push(Line::styled(
                "  (No extra flags configured)",
                theme.footer_desc,
            ));
        } else {
            for flag in &prof.flags {
                lines.push(Line::from(format!("  [x] {}", flag)));
            }
        }

        lines
    } else {
        vec![Line::styled(
            "Select a profile on the left to inspect details.",
            theme.footer_desc,
        )]
    };

    let p = Paragraph::new(content)
        .block(block)
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

    let lines: Vec<Line> = if app.logs.is_empty() {
        vec![Line::styled(
            "Session logs will appear here during connection.",
            theme.footer_desc,
        )]
    } else {
        app.logs
            .iter()
            .rev()
            .take(area.height.saturating_sub(2) as usize)
            .rev()
            .map(|l| Line::raw(l.as_str()))
            .collect()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Connection Logs ");

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

fn render_footer(f: &mut Frame, active_pane: ActivePane, theme: &Theme, area: Rect) {
    let spans = match active_pane {
        ActivePane::Accounts => vec![
            Span::styled(" [a]", theme.footer_key),
            Span::styled(" Add Acc ", theme.footer_desc),
            Span::styled(" [e]", theme.footer_key),
            Span::styled(" Edit ", theme.footer_desc),
            Span::styled(" [x]", theme.footer_key),
            Span::styled(" Delete ", theme.footer_desc),
            Span::styled(" [Tab]", theme.footer_key),
            Span::styled(" Switch Pane ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
        ActivePane::Profiles => vec![
            Span::styled(" [Enter]", theme.footer_key),
            Span::styled(" Connect ", theme.footer_desc),
            Span::styled(" [d]", theme.footer_key),
            Span::styled(" Disconnect ", theme.footer_desc),
            Span::styled(" [p]", theme.footer_key),
            Span::styled(" Ping All ", theme.footer_desc),
            Span::styled(" [n]", theme.footer_key),
            Span::styled(" New Config ", theme.footer_desc),
            Span::styled(" [e]", theme.footer_key),
            Span::styled(" Edit ", theme.footer_desc),
            Span::styled(" [x]", theme.footer_key),
            Span::styled(" Delete ", theme.footer_desc),
            Span::styled(" [Tab]", theme.footer_key),
            Span::styled(" Switch Pane ", theme.footer_desc),
            Span::styled(" [q]", theme.footer_key),
            Span::styled(" Quit ", theme.footer_desc),
        ],
        _ => vec![
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
    }
}
