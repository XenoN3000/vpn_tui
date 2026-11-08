use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{Event, EventStream};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::stdout;
use std::time::Duration;
use vpn_tui::app::App;
use vpn_tui::infra::fs_storage::FsConfigStorage;
use vpn_tui::infra::net_monitor::NetMonitor;
use vpn_tui::infra::process_runner::SudoProcessRunner;
use vpn_tui::infra::tcp_pinger::TcpPinger;
use vpn_tui::ui::modals::render_modal;
use vpn_tui::ui::theme::Theme;
use vpn_tui::ui::views::render_ui;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    // 2. Setup terminal raw mode and alternate screen
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    // 3. Initialize Clean Architecture components
    let storage = FsConfigStorage::new();
    let runner = SudoProcessRunner::new();
    let pinger = TcpPinger::new();
    let mut app = App::new(storage, runner, pinger);
    let mut net_monitor = NetMonitor::new();
    let theme = Theme::default();

    // 4. Async event streams
    let mut reader = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut net_ticker = tokio::time::interval(Duration::from_secs(1));

    // 5. Main event loop
    while !app.should_quit {
        terminal.draw(|f| {
            render_ui(f, &app);
            render_modal(f, &app.active_modal, &app.accounts, &theme);
        })?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if app.connection_state.is_connected() {
                    let _ = app.disconnect().await;
                }
                app.should_quit = true;
            }
            log_event = async {
                match &mut app.event_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(ev) = log_event {
                    app.handle_log_event(ev);
                }
            }
            Some(Ok(Event::Key(key))) = reader.next() => {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    let res = app.handle_key(key.code).await;
                    if let Err(e) = res {
                        app.add_log(format!("Action error: {}", e));
                    }
                }
            }
            _ = net_ticker.tick() => {
                if let vpn_tui::domain::state::ConnectionState::Connected { interface, .. } = &app.connection_state {
                    let stats = net_monitor.read_interface(interface);
                    app.update_net_stats(stats);
                } else {
                    app.update_net_stats(None);
                }
            }
            _ = ticker.tick() => {
                // Redraw on timer tick for responsive UI updates and drain any buffered logs
                app.poll_log_events();
            }
        }
    }

    // 6. Cleanup and restore terminal
    if app.connection_state.is_connected() {
        let _ = app.disconnect().await;
    }
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
