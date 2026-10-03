use super::theme::Theme;
use crate::app::ActiveModal;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

/// Helper function to create a centered rect using percentages of max sizes
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn render_modal(
    f: &mut Frame,
    modal: &ActiveModal,
    accounts: &[crate::domain::account::Account],
    theme: &Theme,
) {
    match modal {
        ActiveModal::None => {}
        ActiveModal::SudoPassword { input, error } => {
            render_sudo_modal(f, input, error.as_deref(), theme);
        }
        ActiveModal::Account(acc_state) => {
            render_account_modal(f, acc_state, theme);
        }
        ActiveModal::ConfigAdder(adder) => {
            render_config_adder_modal(f, adder, accounts, theme);
        }
        ActiveModal::FileBrowser { state, .. } => {
            render_file_browser_modal(f, state, theme);
        }
        ActiveModal::ConfirmDelete { target } => {
            render_confirm_delete_modal(f, target, theme);
        }
        ActiveModal::CertWarning(cert_state) => {
            render_cert_warning_modal(f, cert_state, theme);
        }
    }
}

fn render_sudo_modal(f: &mut Frame, input: &str, error: Option<&str>, theme: &Theme) {
    let area = centered_rect(50, 25, f.area());
    f.render_widget(Clear, area);

    let masked_password: String = "*".repeat(input.len());
    let mut lines = vec![
        Line::raw("Enter sudo password to establish the VPN tunnel:"),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Password: [ ", theme.footer_key),
            Span::styled(format!("{}_", masked_password), theme.text),
            Span::styled(" ]", theme.footer_key),
        ]),
    ];

    if let Some(err) = error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(err, theme.failed));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("[Enter]", theme.footer_key),
        Span::raw(" Confirm   "),
        Span::styled("[Esc]", theme.footer_key),
        Span::raw(" Cancel"),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_active)
        .title(" Sudo Authentication Required ");

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

pub fn render_account_modal(
    f: &mut Frame,
    acc_state: &crate::app::AccountModalState,
    theme: &Theme,
) {
    let area = centered_rect(60, 45, f.area());
    f.render_widget(Clear, area);

    let masked_pass: String = "*".repeat(acc_state.password.len());
    let cursor = |idx: usize| {
        if acc_state.field_idx == idx {
            "▶ "
        } else {
            "  "
        }
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(cursor(0), theme.footer_key),
            Span::styled("Account Name: ", theme.footer_key),
            Span::raw(format!("{}_", acc_state.name)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(cursor(1), theme.footer_key),
            Span::styled("Username:     ", theme.footer_key),
            Span::raw(format!("{}_", acc_state.username)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(cursor(2), theme.footer_key),
            Span::styled("Password:     ", theme.footer_key),
            Span::raw(format!("{}_", masked_pass)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(cursor(3), theme.footer_key),
            Span::styled("Authgroup:    ", theme.footer_key),
            Span::raw(format!("{}_", acc_state.authgroup)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("[Tab/↓]", theme.footer_key),
            Span::raw(" Next Field   "),
            Span::styled("[BackTab/↑]", theme.footer_key),
            Span::raw(" Prev Field   "),
            Span::styled("[Enter]", theme.footer_key),
            Span::raw(" Save   "),
            Span::styled("[Esc]", theme.footer_key),
            Span::raw(" Cancel"),
        ]),
    ];

    let title = if acc_state.editing_account_id.is_some() {
        " Edit Account "
    } else {
        " Add New Account "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_active)
        .title(title);

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

pub fn render_config_adder_modal(
    f: &mut Frame,
    adder: &crate::app::ConfigAdderState,
    accounts: &[crate::domain::account::Account],
    theme: &Theme,
) {
    let area = centered_rect(72, 75, f.area());
    f.render_widget(Clear, area);

    let cursor = |idx: usize| {
        if adder.field_idx == idx { "▶ " } else { "  " }
    };

    let field_style = |idx: usize| {
        if adder.field_idx == idx {
            theme.footer_key
        } else {
            theme.text
        }
    };

    let acc_name = adder
        .account_idx
        .and_then(|idx| accounts.get(idx))
        .map(|a| a.name.as_str())
        .unwrap_or("(None)");

    let mut lines = Vec::new();

    // Field 0: Protocol
    lines.push(Line::from(vec![
        Span::styled(cursor(0), theme.footer_key),
        Span::styled("Protocol:       ", field_style(0)),
        Span::raw(format!("< {} > (Space to change)", adder.protocol)),
    ]));
    lines.push(Line::raw(""));

    // Field 1: Account
    lines.push(Line::from(vec![
        Span::styled(cursor(1), theme.footer_key),
        Span::styled("Parent Account: ", field_style(1)),
        Span::raw(format!("< {} > (Space to cycle)", acc_name)),
    ]));
    lines.push(Line::raw(""));

    match adder.protocol {
        crate::domain::config::VpnProtocol::OpenConnect => {
            let variant = crate::app::OC_VARIANTS[adder.oc_variant_idx];

            // Field 2: Profile Name
            lines.push(Line::from(vec![
                Span::styled(cursor(2), theme.footer_key),
                Span::styled("Profile Name:   ", field_style(2)),
                Span::raw(format!("{}_", adder.oc_name)),
            ]));
            lines.push(Line::raw(""));

            // Field 3: Endpoint
            lines.push(Line::from(vec![
                Span::styled(cursor(3), theme.footer_key),
                Span::styled("Gateway/Host:   ", field_style(3)),
                Span::raw(format!("{}_", adder.oc_endpoint)),
            ]));
            lines.push(Line::raw(""));

            // Field 4: Protocol Variant
            lines.push(Line::from(vec![
                Span::styled(cursor(4), theme.footer_key),
                Span::styled("Variant:        ", field_style(4)),
                Span::raw(format!("< {} > (Space to change)", variant)),
            ]));
            lines.push(Line::raw(""));

            // Field 5: Authgroup
            lines.push(Line::from(vec![
                Span::styled(cursor(5), theme.footer_key),
                Span::styled("Authgroup:      ", field_style(5)),
                Span::raw(format!("{}_", adder.oc_authgroup)),
            ]));
            lines.push(Line::raw(""));

            // Field 6: Servercert
            lines.push(Line::from(vec![
                Span::styled(cursor(6), theme.footer_key),
                Span::styled("Servercert Pin: ", field_style(6)),
                Span::raw(format!("{}_", adder.oc_servercert)),
            ]));
            lines.push(Line::raw(""));

            // Field 7: SSL Policy
            lines.push(Line::from(vec![
                Span::styled(cursor(7), theme.footer_key),
                Span::styled("SSL Policy:     ", field_style(7)),
                Span::raw(format!("< {} > (Space to cycle)", adder.ssl_policy)),
            ]));
            lines.push(Line::raw(""));

            // Field 8: Preset --no-dtls
            let dtls_check = if adder.oc_no_dtls { "[x]" } else { "[ ]" };
            lines.push(Line::from(vec![
                Span::styled(cursor(8), theme.footer_key),
                Span::styled("Preset Flags:   ", field_style(8)),
                Span::raw(format!("{} --no-dtls (Space to toggle)", dtls_check)),
            ]));
            lines.push(Line::raw(""));

            // Field 9: Custom Flags
            lines.push(Line::from(vec![
                Span::styled(cursor(9), theme.footer_key),
                Span::styled("Custom Flags:   ", field_style(9)),
                Span::raw(format!("{}_", adder.oc_custom_flags)),
            ]));
        }
        crate::domain::config::VpnProtocol::OpenVpn => {
            // Field 2: Profile Name
            lines.push(Line::from(vec![
                Span::styled(cursor(2), theme.footer_key),
                Span::styled("Profile Name:   ", field_style(2)),
                Span::raw(format!("{}_", adder.ovpn_name)),
            ]));
            lines.push(Line::raw(""));

            // Field 3: .ovpn File Path
            lines.push(Line::from(vec![
                Span::styled(cursor(3), theme.footer_key),
                Span::styled(".ovpn File:     ", field_style(3)),
                Span::raw(format!("{}_", adder.ovpn_path)),
                Span::styled("  [Tab: Complete | F2: Browse]", theme.footer_desc),
            ]));
            lines.push(Line::raw(""));

            // Field 4: Remote Override
            lines.push(Line::from(vec![
                Span::styled(cursor(4), theme.footer_key),
                Span::styled("Remote Override:", field_style(4)),
                Span::raw(format!("{}_", adder.ovpn_remote)),
            ]));
            lines.push(Line::raw(""));

            // Field 5: --redirect-gateway def1
            let gw_check = if adder.ovpn_redirect_gateway {
                "[x]"
            } else {
                "[ ]"
            };
            lines.push(Line::from(vec![
                Span::styled(cursor(5), theme.footer_key),
                Span::styled("Preset Flags:   ", field_style(5)),
                Span::raw(format!("{} --redirect-gateway def1 (Space)", gw_check)),
            ]));
            lines.push(Line::raw(""));

            // Field 6: --dev tun
            let tun_check = if adder.ovpn_dev_tun { "[x]" } else { "[ ]" };
            lines.push(Line::from(vec![
                Span::styled(cursor(6), theme.footer_key),
                Span::styled("Preset Flags:   ", field_style(6)),
                Span::raw(format!("{} --dev tun (Space)", tun_check)),
            ]));
            lines.push(Line::raw(""));

            // Field 7: Custom Flags
            lines.push(Line::from(vec![
                Span::styled(cursor(7), theme.footer_key),
                Span::styled("Custom Flags:   ", field_style(7)),
                Span::raw(format!("{}_", adder.ovpn_custom_flags)),
            ]));
        }
    }

    if let Some(err) = &adder.error_msg {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("Error: {}", err), theme.failed));
    }

    lines.push(Line::raw(""));
    let mut footer_spans = vec![
        Span::styled("[Tab/↓]", theme.footer_key),
        Span::raw(" Next   "),
        Span::styled("[BackTab/↑]", theme.footer_key),
        Span::raw(" Prev   "),
        Span::styled("[Space]", theme.footer_key),
        Span::raw(" Toggle   "),
    ];
    if adder.protocol == crate::domain::config::VpnProtocol::OpenVpn {
        footer_spans.push(Span::styled("[F2]", theme.footer_key));
        footer_spans.push(Span::raw(" Browse   "));
    }
    footer_spans.push(Span::styled("[Enter]", theme.footer_key));
    footer_spans.push(Span::raw(" Save   "));
    footer_spans.push(Span::styled("[Esc]", theme.footer_key));
    footer_spans.push(Span::raw(" Cancel"));
    lines.push(Line::from(footer_spans));

    let title = if adder.editing_profile_id.is_some() {
        format!(" Edit Configuration ({}) ", adder.protocol)
    } else {
        format!(" New Configuration ({}) ", adder.protocol)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_active)
        .title(title);

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

pub fn render_confirm_delete_modal(
    f: &mut Frame,
    target: &crate::app::DeleteTarget,
    theme: &Theme,
) {
    let area = centered_rect(65, 30, f.area());
    f.render_widget(Clear, area);

    let (heading, item_name, extra_desc) = match target {
        crate::app::DeleteTarget::Account { name, .. } => (
            "Are you sure you want to delete this Account?",
            format!("Account: {}", name),
            "Associated configurations will be unlinked, not deleted.",
        ),
        crate::app::DeleteTarget::Profile { name, protocol, .. } => (
            "Are you sure you want to delete this Configuration Profile?",
            format!("Profile: {} ({})", name, protocol),
            "The configuration and associated files will be permanently deleted.",
        ),
    };

    let lines = vec![
        Line::styled(heading, theme.failed),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Target: ", theme.footer_key),
            Span::styled(item_name, theme.text),
        ]),
        Line::styled(extra_desc, theme.footer_desc),
        Line::raw(""),
        Line::from(vec![
            Span::styled("[y / Enter]", theme.failed),
            Span::raw(" Confirm Delete   "),
            Span::styled("[n / Esc]", theme.footer_key),
            Span::raw(" Cancel"),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.failed)
        .title(" Confirm Deletion ");

    let p = Paragraph::new(lines)
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}

pub fn render_cert_warning_modal(
    f: &mut Frame,
    state: &crate::domain::state::CertWarningState,
    theme: &Theme,
) {
    let area = centered_rect(70, 50, f.area());
    f.render_widget(Clear, area);

    let mut lines = vec![
        Line::styled(
            "SECURITY WARNING: Untrusted Server Certificate",
            theme.failed,
        ),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Server Endpoint: ", theme.footer_key),
            Span::styled(&state.endpoint, theme.text),
        ]),
    ];

    if let Some(subject) = &state.subject {
        lines.push(Line::from(vec![
            Span::styled("Certificate CN:  ", theme.footer_key),
            Span::styled(subject, theme.text),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Failure Reason:  ", theme.footer_key),
        Span::styled(&state.reason, theme.failed),
    ]));

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("SHA-256 Pin:     ", theme.footer_key),
        Span::styled(&state.pin, theme.highlight),
    ]));

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Connecting to an untrusted server may expose your network traffic to interception.",
        theme.footer_desc,
    ));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("[r / Esc]", theme.failed),
        Span::raw(" Refuse & Abort (Safe)   "),
        Span::styled("[a / Enter]", theme.connected),
        Span::raw(" Accept & Pin Certificate"),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.failed)
        .title(" Untrusted SSL/TLS Certificate Alert ");

    let p = Paragraph::new(lines)
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}

pub fn render_file_browser_modal(
    f: &mut Frame,
    browser: &crate::ui::file_picker::FileBrowserState,
    theme: &Theme,
) {
    let area = centered_rect(70, 70, f.area());
    f.render_widget(Clear, area);

    let dir_display = browser.current_dir.to_string_lossy();
    let truncated_dir = if dir_display.len() > 50 {
        format!("...{}", &dir_display[dir_display.len() - 47..])
    } else {
        dir_display.to_string()
    };

    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Directory: ", theme.footer_key),
        Span::styled(truncated_dir, theme.highlight),
    ]));
    lines.push(Line::raw(
        "────────────────────────────────────────────────────────────────",
    ));

    if let Some(err) = &browser.error_msg {
        lines.push(Line::styled(format!("Error: {}", err), theme.failed));
    } else if browser.entries.is_empty() {
        lines.push(Line::styled(
            "  (No .ovpn files or subdirectories found)",
            theme.footer_desc,
        ));
    } else {
        let max_visible = (area.height.saturating_sub(7)) as usize;
        let start_idx = if browser.selected_index >= max_visible {
            browser.selected_index - max_visible + 1
        } else {
            0
        };

        for (i, entry) in browser
            .entries
            .iter()
            .enumerate()
            .skip(start_idx)
            .take(max_visible)
        {
            let is_sel = i == browser.selected_index;
            let marker = if is_sel { "▶ " } else { "  " };
            let icon = if entry.is_dir { "📁 " } else { "📄 " };
            let style = if is_sel {
                theme.highlight
            } else if entry.is_dir {
                theme.footer_key
            } else {
                theme.text
            };

            lines.push(Line::from(vec![
                Span::styled(marker, theme.footer_key),
                Span::raw(icon),
                Span::styled(&entry.name, style),
            ]));
        }
    }

    lines.push(Line::raw(
        "────────────────────────────────────────────────────────────────",
    ));
    lines.push(Line::from(vec![
        Span::styled("[↑/↓/j/k]", theme.footer_key),
        Span::raw(" Move   "),
        Span::styled("[Enter]", theme.footer_key),
        Span::raw(" Open/Select   "),
        Span::styled("[Backspace/←]", theme.footer_key),
        Span::raw(" Up Dir   "),
        Span::styled("[Esc]", theme.footer_key),
        Span::raw(" Back"),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_active)
        .title(" Browse OpenVPN (.ovpn) Files ");

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

#[cfg(test)]
pub mod config_adder {
    use super::*;
    use crate::app::ConfigAdderState;
    use crate::domain::config::VpnProtocol;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_config_adder_modal_openconnect() {
        let backend = TestBackend::new(100, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::OpenConnect;
        adder.oc_name = "Work OC".into();
        adder.oc_endpoint = "gateway.corp.com:443".into();

        terminal
            .draw(|f| {
                render_config_adder_modal(f, &adder, &[], &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("New Configuration (OpenConnect)"));
        assert!(buffer.contains("gateway.corp.com:443"));
        assert!(buffer.contains("Servercert Pin:"));
        assert!(buffer.contains("SSL Policy:"));
        assert!(buffer.contains("Prompt on Mismatch"));
        assert!(buffer.contains("--no-dtls"));
    }

    #[test]
    fn test_render_config_adder_modal_openvpn() {
        let backend = TestBackend::new(100, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::OpenVpn;
        adder.ovpn_name = "My OV".into();
        adder.ovpn_path = "/home/user/vpn.ovpn".into();

        terminal
            .draw(|f| {
                render_config_adder_modal(f, &adder, &[], &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("New Configuration (OpenVPN)"));
        assert!(buffer.contains("/home/user/vpn.ovpn"));
        assert!(buffer.contains("F2") && buffer.contains("Browse"));
        assert!(buffer.contains("--redirect-gateway def1"));
    }
}

#[cfg(test)]
pub mod file_browser {
    use super::*;
    use crate::ui::file_picker::{FileBrowserState, FileEntry};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    #[test]
    fn test_render_file_browser_modal() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        let browser = FileBrowserState {
            current_dir: PathBuf::from("/etc/openvpn"),
            entries: vec![
                FileEntry {
                    name: "..".into(),
                    path: PathBuf::from("/etc"),
                    is_dir: true,
                },
                FileEntry {
                    name: "client.ovpn".into(),
                    path: PathBuf::from("/etc/openvpn/client.ovpn"),
                    is_dir: false,
                },
            ],
            selected_index: 1,
            error_msg: None,
        };

        terminal
            .draw(|f| {
                render_file_browser_modal(f, &browser, &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("Browse OpenVPN (.ovpn) Files"));
        assert!(buffer.contains("/etc/openvpn"));
        assert!(buffer.contains("client.ovpn"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_sudo_modal() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        let modal = ActiveModal::SudoPassword {
            input: "secret123".into(),
            error: None,
        };

        terminal
            .draw(|f| {
                render_modal(f, &modal, &[], &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("Sudo Authentication Required"));
        assert!(buffer.contains("*********"));
    }
}

#[cfg(test)]
pub mod confirm_delete {
    use super::*;
    use crate::app::DeleteTarget;
    use crate::domain::account::AccountId;
    use crate::domain::config::{ProfileId, VpnProtocol};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_confirm_delete_modal() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        // 1. Profile delete target
        let profile_target = DeleteTarget::Profile {
            id: ProfileId("prof-1".to_string()),
            name: "Frankfurt DC".to_string(),
            protocol: VpnProtocol::OpenConnect,
        };

        terminal
            .draw(|f| {
                render_confirm_delete_modal(f, &profile_target, &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("Confirm Deletion"));
        assert!(buffer.contains("Frankfurt DC"));
        assert!(buffer.contains("OpenConnect"));
        assert!(buffer.contains("permanently") && buffer.contains("deleted"));
        assert!(buffer.contains("Confirm Delete"));

        // 2. Account delete target
        let account_target = DeleteTarget::Account {
            id: AccountId("acc-1".to_string()),
            name: "Master Account".to_string(),
        };

        terminal
            .draw(|f| {
                render_confirm_delete_modal(f, &account_target, &theme);
            })
            .unwrap();

        let buffer_acc = format!("{:?}", terminal.backend().buffer());
        assert!(buffer_acc.contains("Confirm Deletion"));
        assert!(buffer_acc.contains("Master Account"));
        assert!(buffer_acc.contains("unlinked, not deleted"));
    }
}

#[cfg(test)]
pub mod edit_mode {
    use super::*;
    use crate::app::{AccountModalState, ConfigAdderState};
    use crate::domain::account::AccountId;
    use crate::domain::config::{ProfileId, VpnProtocol};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_edit_mode() {
        let backend = TestBackend::new(100, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        // 1. Config adder in edit mode
        let mut adder = ConfigAdderState::new(None);
        adder.editing_profile_id = Some(ProfileId("prof-edit-1".to_string()));
        adder.protocol = VpnProtocol::OpenConnect;
        adder.oc_name = "Editing OC".to_string();

        terminal
            .draw(|f| {
                render_config_adder_modal(f, &adder, &[], &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("Edit Configuration (OpenConnect)"));
        assert!(buffer.contains("Editing OC"));

        // 2. Account in edit mode vs add mode
        let mut acc_edit = AccountModalState::new();
        acc_edit.editing_account_id = Some(AccountId("acc-123".to_string()));
        acc_edit.name = "My Account".to_string();

        terminal
            .draw(|f| {
                render_account_modal(f, &acc_edit, &theme);
            })
            .unwrap();

        let buffer_acc = format!("{:?}", terminal.backend().buffer());
        assert!(buffer_acc.contains("Edit Account"));

        let acc_add = AccountModalState::new();
        terminal
            .draw(|f| {
                render_account_modal(f, &acc_add, &theme);
            })
            .unwrap();

        let buffer_add = format!("{:?}", terminal.backend().buffer());
        assert!(buffer_add.contains("Add New Account"));
    }
}

#[cfg(test)]
pub mod cert_warning {
    use super::*;
    use crate::domain::config::ProfileId;
    use crate::domain::state::CertWarningState;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_render_cert_warning_modal() {
        let backend = TestBackend::new(100, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        let state = CertWarningState {
            profile_id: ProfileId("frankfurt-oc".into()),
            endpoint: "45.93.169.132:443".into(),
            subject: Some("CN=nl5.cdntak.com".into()),
            pin: "pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=".into(),
            reason: "certificate does not match hostname".into(),
        };

        terminal
            .draw(|f| {
                render_cert_warning_modal(f, &state, &theme);
            })
            .unwrap();

        let buffer = format!("{:?}", terminal.backend().buffer());
        assert!(buffer.contains("Untrusted SSL/TLS Certificate Alert"));
        assert!(buffer.contains("45.93.169.132:443"));
        assert!(buffer.contains("CN=nl5.cdntak.com"));
        assert!(buffer.contains("certificate does not match hostname"));
        assert!(buffer.contains("pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os="));
        assert!(buffer.contains("[r / Esc]") && buffer.contains("Refuse & Abort"));
        assert!(buffer.contains("[a / Enter]") && buffer.contains("Accept & Pin"));
    }
}
