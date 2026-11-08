use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::BorderType;

#[derive(Debug, Clone)]
pub struct Theme {
    pub border_type: BorderType,
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
            border_type: BorderType::Rounded,
            border: Style::default().fg(Color::DarkGray),
            border_active: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            title: Style::default().fg(Color::DarkGray),
            title_active: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            text: Style::default().fg(Color::Reset),
            highlight: Style::default().add_modifier(Modifier::REVERSED),
            connected: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            connecting: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            disconnected: Style::default().fg(Color::DarkGray),
            failed: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            banner: Style::default().bg(Color::Reset).fg(Color::Reset),
            footer_key: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            footer_desc: Style::default().fg(Color::DarkGray),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::text::Line;
    use ratatui::widgets::{Block, Borders, Paragraph};

    #[test]
    fn test_theme_uses_color_reset_and_reversed() {
        let theme = Theme::default();
        assert_eq!(theme.border_type, BorderType::Rounded);
        assert_eq!(theme.banner.bg, Some(Color::Reset));
        assert_eq!(theme.banner.fg, Some(Color::Reset));
        assert_eq!(theme.text.fg, Some(Color::Reset));
        assert!(theme.highlight.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn test_theme_rendering_to_test_backend() {
        let backend = TestBackend::new(40, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::default();

        terminal
            .draw(|f| {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(theme.border_type)
                    .border_style(theme.border_active)
                    .title(" Rounded Block ");
                let p = Paragraph::new(Line::from("Testing terminal theme")).block(block);
                f.render_widget(p, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        // Check for rounded top-left corner '╭'
        assert_eq!(buffer[(0, 0)].symbol(), "╭");
        assert_eq!(buffer[(39, 0)].symbol(), "╮");
        assert_eq!(buffer[(0, 4)].symbol(), "╰");
        assert_eq!(buffer[(39, 4)].symbol(), "╯");
    }
}
