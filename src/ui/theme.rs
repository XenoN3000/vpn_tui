use ratatui::style::{Color, Modifier, Style};

pub struct Theme {
    pub border: Style,
    pub border_active: Style,
    pub title: Style,
    pub title_active: Style,
    pub text: Style,
    pub highlight: Style,
    pub connected: Style,
    pub connecting: Style,
    pub disconnected: Style,
    pub failed: Style,
    pub banner: Style,
    pub footer_key: Style,
    pub footer_desc: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border: Style::default().fg(Color::DarkGray),
            border_active: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            title: Style::default().fg(Color::Gray),
            title_active: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::White),
            highlight: Style::default()
                .bg(Color::Rgb(30, 45, 65))
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            connected: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            connecting: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            disconnected: Style::default().fg(Color::Gray),
            failed: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            banner: Style::default().bg(Color::Rgb(20, 25, 35)).fg(Color::White),
            footer_key: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            footer_desc: Style::default().fg(Color::Gray),
        }
    }
}
