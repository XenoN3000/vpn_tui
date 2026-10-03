use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, SslPolicy, VpnProtocol};
use crate::domain::state::{CertWarningState, ConnectionState, LatencyState};
use crate::infra::net_monitor::NetStats;
use crate::ports::pinger::Pinger;
use crate::ports::storage::ConfigStorage;
use crate::ports::vpn_runner::{CertProbeResult, LogEvent, VpnRunner};
use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    Accounts,
    Profiles,
    Flags,
    Logs,
}

impl ActivePane {
    pub fn next(&self) -> Self {
        match self {
            ActivePane::Accounts => ActivePane::Profiles,
            ActivePane::Profiles => ActivePane::Flags,
            ActivePane::Flags => ActivePane::Logs,
            ActivePane::Logs => ActivePane::Accounts,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ActivePane::Accounts => ActivePane::Logs,
            ActivePane::Profiles => ActivePane::Accounts,
            ActivePane::Flags => ActivePane::Profiles,
            ActivePane::Logs => ActivePane::Flags,
        }
    }
}

pub const OC_VARIANTS: [&str; 5] = ["anyconnect", "pulse", "gp", "f5", "fortinet"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAdderState {
    pub editing_profile_id: Option<ProfileId>,
    pub protocol: VpnProtocol,
    pub account_idx: Option<usize>,
    pub field_idx: usize,

    // OpenConnect fields
    pub oc_name: String,
    pub oc_endpoint: String,
    pub oc_variant_idx: usize,
    pub oc_authgroup: String,
    pub oc_servercert: String,
    pub ssl_policy: SslPolicy,
    pub oc_no_dtls: bool,
    pub oc_custom_flags: String,

    // OpenVPN fields
    pub ovpn_name: String,
    pub ovpn_path: String,
    pub ovpn_remote: String,
    pub ovpn_redirect_gateway: bool,
    pub ovpn_dev_tun: bool,
    pub ovpn_custom_flags: String,

    pub error_msg: Option<String>,
}

impl ConfigAdderState {
    pub fn new(default_account: Option<usize>) -> Self {
        Self {
            editing_profile_id: None,
            protocol: VpnProtocol::OpenConnect,
            account_idx: default_account,
            field_idx: 0,

            oc_name: String::new(),
            oc_endpoint: String::new(),
            oc_variant_idx: 0,
            oc_authgroup: String::new(),
            oc_servercert: String::new(),
            ssl_policy: SslPolicy::Prompt,
            oc_no_dtls: false,
            oc_custom_flags: String::new(),

            ovpn_name: String::new(),
            ovpn_path: String::new(),
            ovpn_remote: String::new(),
            ovpn_redirect_gateway: true,
            ovpn_dev_tun: true,
            ovpn_custom_flags: String::new(),

            error_msg: None,
        }
    }

    pub fn from_profile(profile: &Profile, accounts: &[Account]) -> Self {
        let account_idx = profile
            .account_id
            .as_ref()
            .and_then(|id| accounts.iter().position(|a| a.id == *id));

        let mut state = Self::new(account_idx);
        state.editing_profile_id = Some(profile.id.clone());
        state.protocol = profile.protocol;
        state.ssl_policy = profile.ssl_policy;

        match profile.protocol {
            VpnProtocol::OpenConnect => {
                state.oc_name = profile.name.clone();
                state.oc_endpoint = profile.endpoint.clone();

                let mut custom_flags = Vec::new();
                for flag in &profile.flags {
                    if let Some(variant) = flag.strip_prefix("--protocol=") {
                        if let Some(pos) = OC_VARIANTS.iter().position(|&v| v == variant) {
                            state.oc_variant_idx = pos;
                        }
                    } else if let Some(authgroup) = flag.strip_prefix("--authgroup=") {
                        state.oc_authgroup = authgroup.to_string();
                    } else if let Some(servercert) = flag.strip_prefix("--servercert=") {
                        state.oc_servercert = servercert.to_string();
                    } else if flag == "--no-dtls" {
                        state.oc_no_dtls = true;
                    } else {
                        custom_flags.push(flag.clone());
                    }
                }
                state.oc_custom_flags = custom_flags.join(" ");
            }
            VpnProtocol::OpenVpn => {
                state.ovpn_name = profile.name.clone();
                state.ovpn_remote = profile.endpoint.clone();
                if let Some(path) = &profile.ovpn_file {
                    state.ovpn_path = path.to_string_lossy().to_string();
                }

                state.ovpn_redirect_gateway = false;
                state.ovpn_dev_tun = false;
                let mut custom_flags = Vec::new();
                let mut iter = profile.flags.iter().peekable();
                while let Some(flag) = iter.next() {
                    if flag == "--redirect-gateway" {
                        if iter.peek().map(|s| s.as_str()) == Some("def1") {
                            iter.next();
                        }
                        state.ovpn_redirect_gateway = true;
                    } else if flag == "--redirect-gateway def1" {
                        state.ovpn_redirect_gateway = true;
                    } else if flag == "--dev" {
                        if iter.peek().map(|s| s.as_str()) == Some("tun") {
                            iter.next();
                        }
                        state.ovpn_dev_tun = true;
                    } else if flag == "--dev tun" {
                        state.ovpn_dev_tun = true;
                    } else {
                        custom_flags.push(flag.clone());
                    }
                }
                state.ovpn_custom_flags = custom_flags.join(" ");
            }
        }

        state
    }

    pub fn total_fields(&self) -> usize {
        match self.protocol {
            VpnProtocol::OpenConnect => 10,
            VpnProtocol::OpenVpn => 8,
        }
    }

    pub fn next_field(&mut self) {
        let total = self.total_fields();
        self.field_idx = (self.field_idx + 1) % total;
    }

    pub fn prev_field(&mut self) {
        let total = self.total_fields();
        self.field_idx = if self.field_idx == 0 {
            total.saturating_sub(1)
        } else {
            self.field_idx - 1
        };
    }
}

pub fn next_account_idx(curr: Option<usize>, num_accounts: usize) -> Option<usize> {
    if num_accounts == 0 {
        return None;
    }
    match curr {
        None => Some(0),
        Some(idx) => {
            if idx + 1 >= num_accounts {
                None
            } else {
                Some(idx + 1)
            }
        }
    }
}

pub fn prev_account_idx(curr: Option<usize>, num_accounts: usize) -> Option<usize> {
    if num_accounts == 0 {
        return None;
    }
    match curr {
        None => Some(num_accounts - 1),
        Some(0) => None,
        Some(idx) => Some(idx - 1),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountModalState {
    pub editing_account_id: Option<AccountId>,
    pub name: String,
    pub username: String,
    pub password: String,
    pub authgroup: String,
    pub field_idx: usize,
}

impl AccountModalState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_account(account: &Account) -> Self {
        let creds = account.credentials.as_ref();
        Self {
            editing_account_id: Some(account.id.clone()),
            name: account.name.clone(),
            username: creds.and_then(|c| c.username.clone()).unwrap_or_default(),
            password: creds.and_then(|c| c.password.clone()).unwrap_or_default(),
            authgroup: creds.and_then(|c| c.auth_group.clone()).unwrap_or_default(),
            field_idx: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTarget {
    Account {
        id: AccountId,
        name: String,
    },
    Profile {
        id: ProfileId,
        name: String,
        protocol: VpnProtocol,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    SudoPassword {
        input: String,
        error: Option<String>,
    },
    Account(AccountModalState),
    ConfigAdder(ConfigAdderState),
    FileBrowser {
        state: crate::ui::file_picker::FileBrowserState,
        parent_adder: ConfigAdderState,
    },
    ConfirmDelete {
        target: DeleteTarget,
    },
    CertWarning(CertWarningState),
}

pub struct App<S: ConfigStorage, R: VpnRunner, P: Pinger> {
    pub storage: S,
    pub runner: R,
    pub pinger: P,

    pub accounts: Vec<Account>,
    pub selected_account_idx: usize,

    pub profiles: Vec<Profile>,
    pub selected_profile_idx: usize,

    pub active_pane: ActivePane,
    pub active_modal: ActiveModal,

    pub connection_state: ConnectionState,
    pub active_profile_name: Option<String>,
    pub net_stats: Option<NetStats>,
    pub logs: Vec<String>,

    pub event_tx: Option<mpsc::UnboundedSender<LogEvent>>,
    pub event_rx: Option<mpsc::UnboundedReceiver<LogEvent>>,
    pub should_quit: bool,
}

impl<S: ConfigStorage, R: VpnRunner, P: Pinger> App<S, R, P> {
    pub fn new(storage: S, runner: R, pinger: P) -> Self {
        let accounts = storage.load_accounts().unwrap_or_default();
        let profiles = storage.load_profiles(None).unwrap_or_default();

        Self {
            storage,
            runner,
            pinger,
            accounts,
            selected_account_idx: 0,
            profiles,
            selected_profile_idx: 0,
            active_pane: ActivePane::Profiles,
            active_modal: ActiveModal::None,
            connection_state: ConnectionState::Disconnected,
            active_profile_name: None,
            net_stats: None,
            logs: Vec::new(),
            event_tx: None,
            event_rx: None,
            should_quit: false,
        }
    }

    pub fn poll_log_events(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &mut self.event_rx {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }
        for event in events {
            self.handle_log_event(event);
        }
    }

    pub fn selected_account(&self) -> Option<&Account> {
        self.accounts.get(self.selected_account_idx)
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        self.profiles.get(self.selected_profile_idx)
    }

    pub fn next_pane(&mut self) {
        self.active_pane = self.active_pane.next();
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = self.active_pane.prev();
    }

    pub fn select_next(&mut self) {
        match self.active_pane {
            ActivePane::Accounts if !self.accounts.is_empty() => {
                self.selected_account_idx = (self.selected_account_idx + 1) % self.accounts.len();
            }
            ActivePane::Profiles if !self.profiles.is_empty() => {
                self.selected_profile_idx = (self.selected_profile_idx + 1) % self.profiles.len();
            }
            _ => {}
        }
    }

    pub fn select_prev(&mut self) {
        match self.active_pane {
            ActivePane::Accounts if !self.accounts.is_empty() => {
                if self.selected_account_idx == 0 {
                    self.selected_account_idx = self.accounts.len() - 1;
                } else {
                    self.selected_account_idx -= 1;
                }
            }
            ActivePane::Profiles if !self.profiles.is_empty() => {
                if self.selected_profile_idx == 0 {
                    self.selected_profile_idx = self.profiles.len() - 1;
                } else {
                    self.selected_profile_idx -= 1;
                }
            }
            _ => {}
        }
    }

    pub fn add_log(&mut self, log: impl Into<String>) {
        let msg = log.into();
        self.logs.push(msg);
        if self.logs.len() > 500 {
            self.logs.remove(0);
        }
    }

    pub async fn ping_all(&mut self) {
        for profile in &mut self.profiles {
            profile.latency = LatencyState::Pinging;
        }

        let mut results = Vec::new();
        for profile in &self.profiles {
            let latency = self
                .pinger
                .ping(&profile.endpoint, Duration::from_secs(2))
                .await;
            results.push((profile.id.clone(), latency));
        }

        for (id, latency) in results {
            if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
                p.latency = latency;
            }
        }
    }

    pub async fn connect_current(&mut self) -> Result<()> {
        let profile = match self.selected_profile() {
            Some(p) => p.clone(),
            None => {
                self.add_log("No profile selected");
                return Ok(());
            }
        };

        // Pre-flight probe for OpenConnect profiles
        if profile.protocol == VpnProtocol::OpenConnect {
            let probe_res = self.runner.probe_endpoint_cert(&profile).await;
            match probe_res {
                CertProbeResult::Trusted => {}
                CertProbeResult::Warning {
                    endpoint,
                    subject,
                    pin,
                    reason,
                } => match profile.ssl_policy {
                    SslPolicy::Strict => {
                        let err_msg = format!("Untrusted certificate on {}: {}", endpoint, reason);
                        self.add_log(format!(
                            "Connection aborted (Strict SSL policy): {}",
                            err_msg
                        ));
                        self.connection_state = ConnectionState::Failed { error: err_msg };
                        return Ok(());
                    }
                    SslPolicy::Prompt => {
                        self.active_modal = ActiveModal::CertWarning(CertWarningState {
                            profile_id: profile.id.clone(),
                            endpoint,
                            subject,
                            pin,
                            reason,
                        });
                        return Ok(());
                    }
                    SslPolicy::Insecure => {}
                },
                CertProbeResult::Failed(err) => {
                    if profile.ssl_policy == SslPolicy::Strict {
                        self.add_log(format!(
                            "Connection aborted (Strict SSL policy probe failure): {}",
                            err
                        ));
                        self.connection_state = ConnectionState::Failed {
                            error: format!("Certificate probe failed: {}", err),
                        };
                        return Ok(());
                    }
                    self.add_log(format!(
                        "Pre-flight probe notice for {}: {}",
                        profile.endpoint, err
                    ));
                }
            }
        }

        if !self.runner.check_sudo_cached().await {
            self.active_modal = ActiveModal::SudoPassword {
                input: String::new(),
                error: None,
            };
            return Ok(());
        }

        self.execute_connect(profile, None).await
    }

    pub async fn execute_connect(
        &mut self,
        profile: Profile,
        sudo_pass: Option<String>,
    ) -> Result<()> {
        if self.connection_state.is_connected() || self.connection_state.can_disconnect() {
            let _ = self.disconnect().await;
        }

        self.connection_state = ConnectionState::Connecting { started_at_secs: 0 };
        self.active_profile_name = Some(profile.name.clone());
        self.add_log(format!("Initiating connection to {}...", profile.name));

        let (tx, rx) = mpsc::unbounded_channel();
        self.event_tx = Some(tx.clone());
        self.event_rx = Some(rx);

        let creds = profile
            .account_id
            .as_ref()
            .and_then(|id| self.accounts.iter().find(|a| a.id == *id))
            .or_else(|| self.selected_account())
            .and_then(|a| a.credentials.as_ref());
        let res = self
            .runner
            .connect(&profile, creds, sudo_pass.as_deref(), tx)
            .await;

        match res {
            Ok(()) => {
                self.poll_log_events();
            }
            Err(e) => {
                self.connection_state = ConnectionState::Failed {
                    error: e.to_string(),
                };
                self.add_log(format!("Connection error: {}", e));
                self.event_rx = None;
                self.event_tx = None;
            }
        }

        Ok(())
    }

    pub fn handle_log_event(&mut self, event: LogEvent) {
        match event {
            LogEvent::Stdout(line) => self.add_log(format!("[INFO] {}", line)),
            LogEvent::Stderr(line) => self.add_log(format!("[ERR]  {}", line)),
            LogEvent::StatusChange(status) => self.add_log(format!("[STAT] {}", status)),
            LogEvent::TunnelUp { interface, ip } => {
                self.connection_state = ConnectionState::Connected {
                    interface: interface.clone(),
                    assigned_ip: ip.clone(),
                    connected_at_secs: 0,
                };
                self.add_log(format!(
                    "VPN Tunnel established on {} ({})",
                    interface,
                    ip.unwrap_or_else(|| "IP unknown".into())
                ));
            }
            LogEvent::ProcessExited(code) => {
                self.connection_state = if code == 0 {
                    ConnectionState::Disconnected
                } else {
                    ConnectionState::Failed {
                        error: format!("Process exited with code {}", code),
                    }
                };
                self.add_log(format!("VPN process terminated (code {})", code));
                self.event_rx = None;
                self.event_tx = None;
            }
        }
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.connection_state = ConnectionState::Disconnecting;
        self.add_log("Disconnecting VPN...");
        self.runner.disconnect().await?;
        self.connection_state = ConnectionState::Disconnected;
        self.active_profile_name = None;
        self.event_rx = None;
        self.event_tx = None;
        self.add_log("Disconnected.");
        Ok(())
    }

    pub async fn handle_key(&mut self, code: crossterm::event::KeyCode) -> Result<()> {
        use crossterm::event::KeyCode;

        let modal = std::mem::replace(&mut self.active_modal, ActiveModal::None);
        match modal {
            ActiveModal::SudoPassword {
                mut input,
                mut error,
            } => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.active_modal = ActiveModal::SudoPassword { input, error };
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    self.active_modal = ActiveModal::SudoPassword { input, error };
                }
                KeyCode::Enter => {
                    let password = input.clone();
                    if let Some(prof) = self.selected_profile().cloned() {
                        self.execute_connect(prof, Some(password)).await?;
                    } else {
                        error = Some("No profile selected".into());
                        self.active_modal = ActiveModal::SudoPassword { input, error };
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::SudoPassword { input, error };
                }
            },
            ActiveModal::Account(mut state) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Tab | KeyCode::Down => {
                    state.field_idx = (state.field_idx + 1) % 4;
                    self.active_modal = ActiveModal::Account(state);
                }
                KeyCode::BackTab | KeyCode::Up => {
                    state.field_idx = if state.field_idx == 0 {
                        3
                    } else {
                        state.field_idx - 1
                    };
                    self.active_modal = ActiveModal::Account(state);
                }
                KeyCode::Backspace => {
                    match state.field_idx {
                        0 => {
                            state.name.pop();
                        }
                        1 => {
                            state.username.pop();
                        }
                        2 => {
                            state.password.pop();
                        }
                        3 => {
                            state.authgroup.pop();
                        }
                        _ => {}
                    }
                    self.active_modal = ActiveModal::Account(state);
                }
                KeyCode::Char(c) => {
                    match state.field_idx {
                        0 => state.name.push(c),
                        1 => state.username.push(c),
                        2 => state.password.push(c),
                        3 => state.authgroup.push(c),
                        _ => {}
                    }
                    self.active_modal = ActiveModal::Account(state);
                }
                KeyCode::Enter => {
                    if !state.name.trim().is_empty() {
                        let mut acc = if let Some(id) = state.editing_account_id {
                            let mut a = Account::new(state.name.trim());
                            a.id = id;
                            a
                        } else {
                            Account::new(state.name.trim())
                        };
                        let creds = crate::domain::account::Credentials {
                            username: if state.username.trim().is_empty() {
                                None
                            } else {
                                Some(state.username.trim().into())
                            },
                            password: if state.password.trim().is_empty() {
                                None
                            } else {
                                Some(state.password.trim().into())
                            },
                            auth_group: if state.authgroup.trim().is_empty() {
                                None
                            } else {
                                Some(state.authgroup.trim().into())
                            },
                            cert_path: None,
                            token: None,
                        };
                        acc = acc.with_credentials(creds);
                        self.storage.save_account(&acc)?;
                        self.accounts = self.storage.load_accounts().unwrap_or_default();
                    }
                    self.active_modal = ActiveModal::None;
                }
                _ => {
                    self.active_modal = ActiveModal::Account(state);
                }
            },

            ActiveModal::ConfigAdder(mut adder) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Tab => {
                    if adder.protocol == VpnProtocol::OpenVpn
                        && adder.field_idx == 3
                        && !adder.ovpn_path.is_empty()
                        && let Some(completed) =
                            crate::ui::file_picker::complete_path(&adder.ovpn_path)
                        && completed != adder.ovpn_path
                    {
                        adder.ovpn_path = completed;
                        self.active_modal = ActiveModal::ConfigAdder(adder);
                        return Ok(());
                    }
                    adder.next_field();
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::BackTab => {
                    adder.prev_field();
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Down => {
                    adder.next_field();
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Up => {
                    adder.prev_field();
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::F(2) => {
                    if adder.protocol == VpnProtocol::OpenVpn {
                        let initial = if !adder.ovpn_path.trim().is_empty() {
                            Some(std::path::PathBuf::from(adder.ovpn_path.trim()))
                        } else {
                            None
                        };
                        self.active_modal = ActiveModal::FileBrowser {
                            state: crate::ui::file_picker::FileBrowserState::new(initial),
                            parent_adder: adder,
                        };
                    } else {
                        self.active_modal = ActiveModal::ConfigAdder(adder);
                    }
                }
                KeyCode::Char(' ') => {
                    match adder.protocol {
                        VpnProtocol::OpenConnect => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenVpn;
                                adder.field_idx = 0;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            4 => {
                                adder.oc_variant_idx =
                                    (adder.oc_variant_idx + 1) % OC_VARIANTS.len();
                            }
                            7 => {
                                adder.ssl_policy = adder.ssl_policy.next();
                            }
                            8 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            2 => adder.oc_name.push(' '),
                            3 => adder.oc_endpoint.push(' '),
                            5 => adder.oc_authgroup.push(' '),
                            6 => adder.oc_servercert.push(' '),
                            9 => adder.oc_custom_flags.push(' '),
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenConnect;
                                adder.field_idx = 0;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            6 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            2 => adder.ovpn_name.push(' '),
                            3 => adder.ovpn_path.push(' '),
                            4 => adder.ovpn_remote.push(' '),
                            7 => adder.ovpn_custom_flags.push(' '),
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Left => {
                    match adder.protocol {
                        VpnProtocol::OpenConnect => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenVpn;
                            }
                            1 => {
                                adder.account_idx =
                                    prev_account_idx(adder.account_idx, self.accounts.len());
                            }
                            4 => {
                                adder.oc_variant_idx = if adder.oc_variant_idx == 0 {
                                    OC_VARIANTS.len() - 1
                                } else {
                                    adder.oc_variant_idx - 1
                                };
                            }
                            7 => {
                                adder.ssl_policy = match adder.ssl_policy {
                                    SslPolicy::Prompt => SslPolicy::Insecure,
                                    SslPolicy::Strict => SslPolicy::Prompt,
                                    SslPolicy::Insecure => SslPolicy::Strict,
                                };
                            }
                            8 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenConnect;
                            }
                            1 => {
                                adder.account_idx =
                                    prev_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            6 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Right => {
                    match adder.protocol {
                        VpnProtocol::OpenConnect => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenVpn;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            4 => {
                                adder.oc_variant_idx =
                                    (adder.oc_variant_idx + 1) % OC_VARIANTS.len();
                            }
                            7 => {
                                adder.ssl_policy = adder.ssl_policy.next();
                            }
                            8 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenConnect;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            6 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Backspace => {
                    match adder.protocol {
                        VpnProtocol::OpenConnect => match adder.field_idx {
                            2 => {
                                adder.oc_name.pop();
                            }
                            3 => {
                                adder.oc_endpoint.pop();
                            }
                            5 => {
                                adder.oc_authgroup.pop();
                            }
                            6 => {
                                adder.oc_servercert.pop();
                            }
                            9 => {
                                adder.oc_custom_flags.pop();
                            }
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            2 => {
                                adder.ovpn_name.pop();
                            }
                            3 => {
                                adder.ovpn_path.pop();
                            }
                            4 => {
                                adder.ovpn_remote.pop();
                            }
                            7 => {
                                adder.ovpn_custom_flags.pop();
                            }
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Char(c) => {
                    match adder.protocol {
                        VpnProtocol::OpenConnect => match adder.field_idx {
                            2 => adder.oc_name.push(c),
                            3 => adder.oc_endpoint.push(c),
                            5 => adder.oc_authgroup.push(c),
                            6 => adder.oc_servercert.push(c),
                            9 => adder.oc_custom_flags.push(c),
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            2 => adder.ovpn_name.push(c),
                            3 => adder.ovpn_path.push(c),
                            4 => adder.ovpn_remote.push(c),
                            7 => adder.ovpn_custom_flags.push(c),
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Enter => {
                    self.submit_config_adder(adder)?;
                }
                _ => {
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
            },
            ActiveModal::FileBrowser {
                mut state,
                mut parent_adder,
            } => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::ConfigAdder(parent_adder);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state.select_next();
                    self.active_modal = ActiveModal::FileBrowser {
                        state,
                        parent_adder,
                    };
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    state.select_prev();
                    self.active_modal = ActiveModal::FileBrowser {
                        state,
                        parent_adder,
                    };
                }
                KeyCode::Backspace | KeyCode::Left => {
                    state.go_up();
                    self.active_modal = ActiveModal::FileBrowser {
                        state,
                        parent_adder,
                    };
                }
                KeyCode::Enter => {
                    if let Some(selected_file) = state.enter_selected() {
                        parent_adder.ovpn_path = selected_file.to_string_lossy().to_string();
                        if parent_adder.ovpn_name.trim().is_empty()
                            && let Some(stem) = selected_file.file_stem().and_then(|s| s.to_str())
                        {
                            parent_adder.ovpn_name = stem.to_string();
                        }
                        self.active_modal = ActiveModal::ConfigAdder(parent_adder);
                    } else {
                        self.active_modal = ActiveModal::FileBrowser {
                            state,
                            parent_adder,
                        };
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::FileBrowser {
                        state,
                        parent_adder,
                    };
                }
            },
            ActiveModal::ConfirmDelete { target } => match code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    match target {
                        DeleteTarget::Account { id, name } => {
                            self.storage.delete_account(&id)?;
                            for prof in &mut self.profiles {
                                if prof.account_id.as_ref() == Some(&id) {
                                    prof.account_id = None;
                                    self.storage.save_profile(prof)?;
                                }
                            }
                            self.accounts = self.storage.load_accounts().unwrap_or_default();
                            self.profiles = self.storage.load_profiles(None).unwrap_or_default();
                            if self.selected_account_idx >= self.accounts.len()
                                && !self.accounts.is_empty()
                            {
                                self.selected_account_idx = self.accounts.len() - 1;
                            }
                            self.add_log(format!("Deleted account '{}'", name));
                        }
                        DeleteTarget::Profile { id, name, .. } => {
                            self.storage.delete_profile(&id)?;
                            self.profiles = self.storage.load_profiles(None).unwrap_or_default();
                            if self.selected_profile_idx >= self.profiles.len()
                                && !self.profiles.is_empty()
                            {
                                self.selected_profile_idx = self.profiles.len() - 1;
                            }
                            self.add_log(format!("Deleted profile '{}'", name));
                        }
                    }
                    self.active_modal = ActiveModal::None;
                }
                _ => {
                    self.active_modal = ActiveModal::ConfirmDelete { target };
                }
            },
            ActiveModal::CertWarning(state) => match code {
                KeyCode::Esc | KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.add_log(format!(
                        "Server certificate refused by user for {}. Connection aborted.",
                        state.endpoint
                    ));
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Enter | KeyCode::Char('a') | KeyCode::Char('A') => {
                    let pin_flag = format!("--servercert={}", state.pin);
                    let mut target_profile = None;

                    if let Some(prof) = self.profiles.iter_mut().find(|p| p.id == state.profile_id)
                    {
                        if !prof.flags.iter().any(|f| f.starts_with("--servercert")) {
                            prof.flags.push(pin_flag.clone());
                        } else {
                            for f in &mut prof.flags {
                                if f.starts_with("--servercert") {
                                    *f = pin_flag.clone();
                                }
                            }
                        }
                        let _ = self.storage.save_profile(prof);
                        target_profile = Some(prof.clone());
                    }

                    self.add_log(format!(
                        "Pinned certificate for profile '{}': {}",
                        state.profile_id, state.pin
                    ));
                    self.active_modal = ActiveModal::None;

                    if let Some(prof) = target_profile {
                        if !self.runner.check_sudo_cached().await {
                            self.active_modal = ActiveModal::SudoPassword {
                                input: String::new(),
                                error: None,
                            };
                        } else {
                            self.execute_connect(prof, None).await?;
                        }
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::CertWarning(state);
                }
            },
            ActiveModal::None => match code {
                KeyCode::Char('q') => {
                    self.should_quit = true;
                }
                KeyCode::Tab => {
                    self.next_pane();
                }
                KeyCode::BackTab => {
                    self.prev_pane();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.select_next();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.select_prev();
                }
                KeyCode::Enter => {
                    self.connect_current().await?;
                }
                KeyCode::Char('d') => {
                    self.disconnect().await?;
                }
                KeyCode::Char('p') => {
                    self.ping_all().await;
                }
                KeyCode::Char('a') => {
                    self.active_modal = ActiveModal::Account(AccountModalState::new());
                }
                KeyCode::Char('e') => {
                    match self.active_pane {
                        ActivePane::Accounts => {
                            if let Some(acc) = self.selected_account() {
                                self.active_modal =
                                    ActiveModal::Account(AccountModalState::from_account(acc));
                            }
                        }
                        ActivePane::Profiles => {
                            if let Some(prof) = self.selected_profile() {
                                if (self.connection_state.is_connected()
                                    || matches!(
                                        self.connection_state,
                                        ConnectionState::Connecting { .. }
                                    ))
                                    && self.active_profile_name.as_deref() == Some(&prof.name)
                                {
                                    self.add_log("Cannot edit profile while connected. Please disconnect first.");
                                } else {
                                    self.active_modal = ActiveModal::ConfigAdder(
                                        ConfigAdderState::from_profile(prof, &self.accounts),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
                KeyCode::Char('x') | KeyCode::Delete => match self.active_pane {
                    ActivePane::Accounts => {
                        if let Some(acc) = self.selected_account() {
                            self.active_modal = ActiveModal::ConfirmDelete {
                                target: DeleteTarget::Account {
                                    id: acc.id.clone(),
                                    name: acc.name.clone(),
                                },
                            };
                        }
                    }
                    ActivePane::Profiles => {
                        if let Some(prof) = self.selected_profile() {
                            if (self.connection_state.is_connected()
                                || matches!(
                                    self.connection_state,
                                    ConnectionState::Connecting { .. }
                                ))
                                && self.active_profile_name.as_deref() == Some(&prof.name)
                            {
                                self.add_log("Cannot delete profile while connected. Please disconnect first.");
                            } else {
                                self.active_modal = ActiveModal::ConfirmDelete {
                                    target: DeleteTarget::Profile {
                                        id: prof.id.clone(),
                                        name: prof.name.clone(),
                                        protocol: prof.protocol,
                                    },
                                };
                            }
                        }
                    }
                    _ => {}
                },
                KeyCode::Char('n') => {
                    let def_acc = if self.accounts.is_empty() {
                        None
                    } else {
                        Some(
                            self.selected_account_idx
                                .min(self.accounts.len().saturating_sub(1)),
                        )
                    };
                    self.active_modal = ActiveModal::ConfigAdder(ConfigAdderState::new(def_acc));
                }
                _ => {}
            },
        }

        Ok(())
    }

    pub fn submit_config_adder(&mut self, mut adder: ConfigAdderState) -> Result<()> {
        match adder.protocol {
            VpnProtocol::OpenConnect => {
                if adder.oc_name.trim().is_empty() || adder.oc_endpoint.trim().is_empty() {
                    adder.error_msg = Some("Profile name and endpoint are required".to_string());
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                    return Ok(());
                }

                let mut prof =
                    Profile::new_openconnect(adder.oc_name.trim(), adder.oc_endpoint.trim());
                if let Some(id) = adder.editing_profile_id.clone() {
                    prof.id = id;
                }

                let variant = OC_VARIANTS[adder.oc_variant_idx];
                if variant != "anyconnect" {
                    prof = prof.with_flag(format!("--protocol={}", variant));
                }

                if !adder.oc_authgroup.trim().is_empty() {
                    prof = prof.with_flag(format!("--authgroup={}", adder.oc_authgroup.trim()));
                }

                if !adder.oc_servercert.trim().is_empty() {
                    prof = prof.with_flag(format!("--servercert={}", adder.oc_servercert.trim()));
                }

                if adder.oc_no_dtls {
                    prof = prof.with_flag("--no-dtls");
                }

                for f in adder.oc_custom_flags.split_whitespace() {
                    prof = prof.with_flag(f);
                }

                prof = prof.with_ssl_policy(adder.ssl_policy);

                if let Some(idx) = adder.account_idx
                    && let Some(acc) = self.accounts.get(idx)
                {
                    prof = prof.with_account(acc.id.clone());
                }

                self.storage.save_profile(&prof)?;
                self.profiles = self.storage.load_profiles(None).unwrap_or_default();
                self.active_modal = ActiveModal::None;
            }
            VpnProtocol::OpenVpn => {
                let path_str = adder.ovpn_path.trim();
                if !path_str.is_empty() {
                    let p = std::path::Path::new(path_str);
                    let name = if !adder.ovpn_name.trim().is_empty() {
                        adder.ovpn_name.trim().to_string()
                    } else {
                        p.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("openvpn-config")
                            .to_string()
                    };

                    match self.storage.import_ovpn(p, &name) {
                        Ok(mut prof) => {
                            if let Some(id) = adder.editing_profile_id.clone() {
                                prof.id = id;
                            }
                            if !adder.ovpn_remote.trim().is_empty() {
                                prof.endpoint = adder.ovpn_remote.trim().to_string();
                            }
                            if adder.ovpn_redirect_gateway {
                                prof = prof.with_flag("--redirect-gateway").with_flag("def1");
                            }
                            if adder.ovpn_dev_tun {
                                prof = prof.with_flag("--dev").with_flag("tun");
                            }
                            for f in adder.ovpn_custom_flags.split_whitespace() {
                                prof = prof.with_flag(f);
                            }
                            if let Some(idx) = adder.account_idx
                                && let Some(acc) = self.accounts.get(idx)
                            {
                                prof = prof.with_account(acc.id.clone());
                            }
                            self.storage.save_profile(&prof)?;
                            self.profiles = self.storage.load_profiles(None).unwrap_or_default();
                            self.active_modal = ActiveModal::None;
                        }
                        Err(e) => {
                            adder.error_msg = Some(e.to_string());
                            self.active_modal = ActiveModal::ConfigAdder(adder);
                        }
                    }
                } else if !adder.ovpn_name.trim().is_empty() && !adder.ovpn_remote.trim().is_empty()
                {
                    let mut prof = Profile::new_openvpn(
                        adder.ovpn_name.trim(),
                        adder.ovpn_remote.trim(),
                        None,
                    );
                    if let Some(id) = adder.editing_profile_id.clone() {
                        prof.id = id;
                    }
                    if adder.ovpn_redirect_gateway {
                        prof = prof.with_flag("--redirect-gateway").with_flag("def1");
                    }
                    if adder.ovpn_dev_tun {
                        prof = prof.with_flag("--dev").with_flag("tun");
                    }
                    for f in adder.ovpn_custom_flags.split_whitespace() {
                        prof = prof.with_flag(f);
                    }
                    if let Some(idx) = adder.account_idx
                        && let Some(acc) = self.accounts.get(idx)
                    {
                        prof = prof.with_account(acc.id.clone());
                    }
                    self.storage.save_profile(&prof)?;
                    self.profiles = self.storage.load_profiles(None).unwrap_or_default();
                    self.active_modal = ActiveModal::None;
                } else {
                    adder.error_msg =
                        Some("Please provide an .ovpn file path or server endpoint".to_string());
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::pinger::MockPinger;
    use crate::ports::storage::InMemoryStorage;
    use crate::ports::vpn_runner::MockVpnRunner;

    fn setup_app() -> App<InMemoryStorage, MockVpnRunner, MockPinger> {
        let mut storage = InMemoryStorage::new();
        let acc = Account::new("Work");
        storage.save_account(&acc).unwrap();

        let prof = Profile::new_openconnect("Frankfurt", "vpn.frankfurt.com:443");
        storage.save_profile(&prof).unwrap();

        App::new(storage, MockVpnRunner::new(), MockPinger::new())
    }

    #[test]
    fn test_app_initial_state_and_navigation() {
        let mut app = setup_app();
        assert_eq!(app.accounts.len(), 1);
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.active_pane, ActivePane::Profiles);

        app.next_pane();
        assert_eq!(app.active_pane, ActivePane::Flags);

        app.prev_pane();
        assert_eq!(app.active_pane, ActivePane::Profiles);
    }

    #[tokio::test]
    async fn test_app_connect_and_disconnect() {
        let mut app = setup_app();
        assert_eq!(app.connection_state, ConnectionState::Disconnected);

        app.connect_current().await.unwrap();
        assert_eq!(app.active_profile_name.as_deref(), Some("Frankfurt"));
        assert!(app.connection_state.can_disconnect());

        app.disconnect().await.unwrap();
        assert_eq!(app.connection_state, ConnectionState::Disconnected);
        assert_eq!(app.active_profile_name, None);
    }

    #[tokio::test]
    async fn test_app_sudo_modal_trigger_when_not_cached() {
        let mut storage = InMemoryStorage::new();
        let prof = Profile::new_openconnect("Work", "vpn.com:443");
        storage.save_profile(&prof).unwrap();

        let mut app = App::new(
            storage,
            MockVpnRunner::new().with_sudo_cached(false),
            MockPinger::new(),
        );

        app.connect_current().await.unwrap();
        match app.active_modal {
            ActiveModal::SudoPassword { .. } => {}
            other => panic!("Expected SudoPassword modal, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_app_ping_all() {
        let mut app = setup_app();
        assert_eq!(app.profiles[0].latency, LatencyState::Unknown);

        app.ping_all().await;
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(25));
    }

    #[tokio::test]
    async fn test_app_handle_key_navigation_and_modals() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();
        assert_eq!(app.active_pane, ActivePane::Profiles);

        // Tab -> Flags
        app.handle_key(KeyCode::Tab).await.unwrap();
        assert_eq!(app.active_pane, ActivePane::Flags);

        // 'a' -> Account modal
        app.handle_key(KeyCode::Char('a')).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::Account(_)));

        // Esc -> Close modal
        app.handle_key(KeyCode::Esc).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // 'q' -> Should quit
        app.handle_key(KeyCode::Char('q')).await.unwrap();
        assert!(app.should_quit);
    }

    #[tokio::test]
    pub async fn test_app_protocol_switch() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.protocol, VpnProtocol::OpenConnect);
        assert_eq!(adder.field_idx, 0);

        // Toggle protocol with space on field 0
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.protocol, VpnProtocol::OpenVpn);

        // Navigate to account field (field 1)
        app.handle_key(KeyCode::Tab).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 1);

        // Cycle account
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        // Setup app has 1 account, cycling from Some(0) wraps to None
        assert_eq!(adder.account_idx, None);
    }

    #[tokio::test]
    pub async fn test_app_config_submit_openconnect() {
        let mut app = setup_app();

        let mut adder = ConfigAdderState::new(Some(0));
        adder.protocol = VpnProtocol::OpenConnect;
        adder.oc_name = "Office VPN".into();
        adder.oc_endpoint = "vpn.office.com:443".into();
        adder.oc_variant_idx = 1; // "pulse"
        adder.oc_authgroup = "staff".into();
        adder.oc_servercert = "pin-sha256:abc123".into();
        adder.oc_no_dtls = true;
        adder.oc_custom_flags = "--cafile=/etc/cert.pem".into();

        app.submit_config_adder(adder).unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "Office VPN")
            .expect("profile saved");
        assert_eq!(prof.protocol, VpnProtocol::OpenConnect);
        assert_eq!(prof.endpoint, "vpn.office.com:443");
        assert!(prof.flags.contains(&"--protocol=pulse".to_string()));
        assert!(prof.flags.contains(&"--authgroup=staff".to_string()));
        assert!(
            prof.flags
                .contains(&"--servercert=pin-sha256:abc123".to_string())
        );
        assert!(prof.flags.contains(&"--no-dtls".to_string()));
        assert!(prof.flags.contains(&"--cafile=/etc/cert.pem".to_string()));
        assert_eq!(prof.account_id, Some(app.accounts[0].id.clone()));
    }

    #[tokio::test]
    pub async fn test_app_config_adder_ssl_policy_cycling_and_persistence() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        // Navigate to field 7 (SSL Policy)
        for _ in 0..7 {
            app.handle_key(KeyCode::Tab).await.unwrap();
        }

        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 7);
        assert_eq!(adder.ssl_policy, SslPolicy::Prompt);

        // Cycle with space: Prompt -> Strict
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.ssl_policy, SslPolicy::Strict);

        // Cycle with space: Strict -> Insecure
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.ssl_policy, SslPolicy::Insecure);

        // Submit profile with Strict policy
        let mut adder = adder;
        adder.oc_name = "Strict Profile".into();
        adder.oc_endpoint = "strict.vpn.corp:443".into();
        adder.ssl_policy = SslPolicy::Strict;
        app.submit_config_adder(adder).unwrap();

        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "Strict Profile")
            .unwrap();
        assert_eq!(prof.ssl_policy, SslPolicy::Strict);
    }

    #[tokio::test]
    pub async fn test_app_config_submit_openvpn() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut app = setup_app();

        let mut temp_ovpn = NamedTempFile::new().unwrap();
        writeln!(temp_ovpn, "client\ndev tun\nremote 192.168.1.1 1194").unwrap();

        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::OpenVpn;
        adder.ovpn_name = "My OpenVPN".into();
        adder.ovpn_path = temp_ovpn.path().to_string_lossy().to_string();
        adder.ovpn_remote = "vpn.override.com:1194".into();
        adder.ovpn_redirect_gateway = true;
        adder.ovpn_dev_tun = true;
        adder.ovpn_custom_flags = "--verb 4".into();

        app.submit_config_adder(adder).unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "My OpenVPN")
            .expect("profile saved");
        assert_eq!(prof.protocol, VpnProtocol::OpenVpn);
        assert_eq!(prof.endpoint, "vpn.override.com:1194");
        assert!(
            prof.flags.contains(&"--verb".to_string()) || prof.flags.contains(&"4".to_string())
        );
    }

    #[tokio::test]
    pub async fn test_app_file_browser_integration() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        // Switch to OpenVPN
        app.handle_key(KeyCode::Char(' ')).await.unwrap();

        // Press F2 to launch file browser
        app.handle_key(KeyCode::F(2)).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::FileBrowser { .. }));

        // Press Esc to dismiss and return to ConfigAdder
        app.handle_key(KeyCode::Esc).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::ConfigAdder(_)));
    }

    #[test]
    pub(crate) fn test_app_config_edit_init() {
        let acc = Account::new("CorpAccount");
        let mut prof_oc = Profile::new_openconnect("WorkOC", "vpn.work.com:443")
            .with_flag("--protocol=pulse")
            .with_flag("--authgroup=developers")
            .with_flag("--servercert=pin-sha256:abc123xyz")
            .with_flag("--no-dtls")
            .with_flag("--extra-flag");
        prof_oc.account_id = Some(acc.id.clone());

        let state_oc = ConfigAdderState::from_profile(&prof_oc, &[acc.clone()]);
        assert_eq!(state_oc.editing_profile_id, Some(prof_oc.id.clone()));
        assert_eq!(state_oc.protocol, VpnProtocol::OpenConnect);
        assert_eq!(state_oc.oc_name, "WorkOC");
        assert_eq!(state_oc.oc_endpoint, "vpn.work.com:443");
        assert_eq!(state_oc.oc_variant_idx, 1); // "pulse"
        assert_eq!(state_oc.oc_authgroup, "developers");
        assert_eq!(state_oc.oc_servercert, "pin-sha256:abc123xyz");
        assert!(state_oc.oc_no_dtls);
        assert_eq!(state_oc.oc_custom_flags, "--extra-flag");
        assert_eq!(state_oc.account_idx, Some(0));

        let prof_ovpn = Profile::new_openvpn(
            "HomeOVPN",
            "vpn.home.net:1194",
            Some(std::path::PathBuf::from("/etc/openvpn/home.ovpn")),
        )
        .with_flag("--redirect-gateway")
        .with_flag("def1")
        .with_flag("--dev")
        .with_flag("tun")
        .with_flag("--verb")
        .with_flag("3");

        let state_ovpn = ConfigAdderState::from_profile(&prof_ovpn, &[]);
        assert_eq!(state_ovpn.editing_profile_id, Some(prof_ovpn.id.clone()));
        assert_eq!(state_ovpn.protocol, VpnProtocol::OpenVpn);
        assert_eq!(state_ovpn.ovpn_name, "HomeOVPN");
        assert_eq!(state_ovpn.ovpn_remote, "vpn.home.net:1194");
        assert_eq!(state_ovpn.ovpn_path, "/etc/openvpn/home.ovpn");
        assert!(state_ovpn.ovpn_redirect_gateway);
        assert!(state_ovpn.ovpn_dev_tun);
        assert_eq!(state_ovpn.ovpn_custom_flags, "--verb 3");
    }

    #[test]
    pub(crate) fn test_app_account_edit() {
        let new_state = AccountModalState::new();
        assert_eq!(new_state.editing_account_id, None);
        assert!(new_state.name.is_empty());
        assert_eq!(new_state.field_idx, 0);

        let mut acc = Account::new("Personal");
        acc = acc.with_credentials(crate::domain::account::Credentials {
            username: Some("alice".into()),
            password: Some("secretpass".into()),
            auth_group: Some("vpnusers".into()),
            cert_path: None,
            token: None,
        });

        let edit_state = AccountModalState::from_account(&acc);
        assert_eq!(edit_state.editing_account_id, Some(acc.id.clone()));
        assert_eq!(edit_state.name, "Personal");
        assert_eq!(edit_state.username, "alice");
        assert_eq!(edit_state.password, "secretpass");
        assert_eq!(edit_state.authgroup, "vpnusers");
    }

    #[tokio::test]
    pub(crate) async fn test_app_edit_hotkey() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();

        // 1. Edit Profile from ActivePane::Profiles
        app.active_pane = ActivePane::Profiles;
        app.handle_key(KeyCode::Char('e')).await.unwrap();

        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder modal, got {:?}", other),
        };
        assert_eq!(adder.editing_profile_id, Some(app.profiles[0].id.clone()));
        assert_eq!(adder.oc_name, "Frankfurt");

        // Submit edit with changed endpoint
        let mut edited_adder = adder;
        edited_adder.oc_endpoint = "vpn.updated-frankfurt.com:443".into();
        app.submit_config_adder(edited_adder).unwrap();

        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].endpoint, "vpn.updated-frankfurt.com:443");

        // 2. Edit Account from ActivePane::Accounts
        app.active_pane = ActivePane::Accounts;
        app.handle_key(KeyCode::Char('e')).await.unwrap();

        let acc_modal = match &app.active_modal {
            ActiveModal::Account(a) => a.clone(),
            other => panic!("Expected Account modal, got {:?}", other),
        };
        assert_eq!(
            acc_modal.editing_account_id,
            Some(app.accounts[0].id.clone())
        );
        assert_eq!(acc_modal.name, "Work");

        // Modify username and hit Enter
        app.handle_key(KeyCode::Tab).await.unwrap(); // Go to username
        app.handle_key(KeyCode::Char('u')).await.unwrap();
        app.handle_key(KeyCode::Char('1')).await.unwrap();
        app.handle_key(KeyCode::Enter).await.unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(
            app.accounts[0]
                .credentials
                .as_ref()
                .unwrap()
                .username
                .as_deref(),
            Some("u1")
        );

        // 3. Active Connection Guard: Cannot edit connected profile
        app.active_pane = ActivePane::Profiles;
        app.connection_state = ConnectionState::Connected {
            interface: "tun0".into(),
            assigned_ip: Some("10.8.0.2".into()),
            connected_at_secs: 10,
        };
        app.active_profile_name = Some(app.profiles[0].name.clone());

        app.handle_key(KeyCode::Char('e')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Cannot edit profile while connected"))
        );
    }

    #[tokio::test]
    pub(crate) async fn test_app_delete_flow() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();

        // Assign account to profile
        app.profiles[0].account_id = Some(app.accounts[0].id.clone());
        app.storage.save_profile(&app.profiles[0]).unwrap();

        // 1. Delete profile with confirmation
        app.active_pane = ActivePane::Profiles;
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert!(matches!(
            app.active_modal,
            ActiveModal::ConfirmDelete {
                target: DeleteTarget::Profile { .. }
            }
        ));

        // Cancel with 'n'
        app.handle_key(KeyCode::Char('n')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 1);

        // Active connection guard for delete
        app.connection_state = ConnectionState::Connected {
            interface: "tun0".into(),
            assigned_ip: Some("10.8.0.2".into()),
            connected_at_secs: 10,
        };
        app.active_profile_name = Some(app.profiles[0].name.clone());
        app.handle_key(KeyCode::Delete).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Cannot delete profile while connected"))
        );

        // Disconnect and confirm delete
        app.connection_state = ConnectionState::Disconnected;
        app.active_profile_name = None;

        app.handle_key(KeyCode::Char('x')).await.unwrap();
        app.handle_key(KeyCode::Char('y')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 0);

        // 2. Cascade unassign on account delete
        // Re-create a profile linked to account
        let prof = Profile::new_openconnect("Munich", "vpn.munich.com:443")
            .with_account(app.accounts[0].id.clone());
        app.storage.save_profile(&prof).unwrap();
        app.profiles = app.storage.load_profiles(None).unwrap();
        assert_eq!(app.profiles[0].account_id, Some(app.accounts[0].id.clone()));

        // Delete account
        app.active_pane = ActivePane::Accounts;
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert!(matches!(
            app.active_modal,
            ActiveModal::ConfirmDelete {
                target: DeleteTarget::Account { .. }
            }
        ));

        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.accounts.len(), 0);

        // Profile still exists, but account_id is None
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].account_id, None);
    }

    #[tokio::test]
    async fn test_app_preflight_probe_cert_warning_modal() {
        let mut app = setup_app();
        let warning = CertProbeResult::Warning {
            endpoint: "vpn.frankfurt.com:443".into(),
            subject: Some("CN=vpn.frankfurt.com".into()),
            pin: "pin-sha256:abc123testpin=".into(),
            reason: "certificate does not match hostname".into(),
        };
        app.runner = app.runner.with_probe_result(warning);

        app.connect_current().await.unwrap();

        // Prompt policy should show CertWarning modal
        match &app.active_modal {
            ActiveModal::CertWarning(state) => {
                assert_eq!(state.profile_id, app.profiles[0].id);
                assert_eq!(state.endpoint, "vpn.frankfurt.com:443");
                assert_eq!(state.pin, "pin-sha256:abc123testpin=");
                assert_eq!(state.reason, "certificate does not match hostname");
            }
            other => panic!("Expected ActiveModal::CertWarning, got {:?}", other),
        }

        // Connection should not have started
        assert_eq!(app.connection_state, ConnectionState::Disconnected);
        assert!(
            !app.runner
                .is_connected
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn test_app_preflight_probe_strict_policy_aborts() {
        let mut app = setup_app();
        app.profiles[0].ssl_policy = SslPolicy::Strict;
        app.storage.save_profile(&app.profiles[0]).unwrap();

        let warning = CertProbeResult::Warning {
            endpoint: "vpn.frankfurt.com:443".into(),
            subject: Some("CN=vpn.frankfurt.com".into()),
            pin: "pin-sha256:abc123testpin=".into(),
            reason: "signer not found".into(),
        };
        app.runner = app.runner.with_probe_result(warning);

        app.connect_current().await.unwrap();

        // Strict policy should NOT show modal and should abort connection
        assert_eq!(app.active_modal, ActiveModal::None);
        assert!(matches!(
            app.connection_state,
            ConnectionState::Failed { .. }
        ));
        assert!(
            !app.runner
                .is_connected
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(app.logs.iter().any(|l| l.contains("Strict SSL policy")));
    }

    #[tokio::test]
    async fn test_app_cert_warning_refuse_aborts() {
        let mut app = setup_app();
        app.active_modal = ActiveModal::CertWarning(CertWarningState {
            profile_id: app.profiles[0].id.clone(),
            endpoint: "vpn.frankfurt.com:443".into(),
            subject: None,
            pin: "pin-sha256:test".into(),
            reason: "mismatch".into(),
        });

        // Refuse with 'r'
        app.handle_key(crossterm::event::KeyCode::Char('r'))
            .await
            .unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.connection_state, ConnectionState::Disconnected);
        assert!(
            !app.runner
                .is_connected
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(app.logs.iter().any(|l| l.contains("refused by user")));
    }

    #[tokio::test]
    async fn test_app_cert_warning_accept_pins_and_connects() {
        let mut app = setup_app();
        let prof_id = app.profiles[0].id.clone();
        app.active_modal = ActiveModal::CertWarning(CertWarningState {
            profile_id: prof_id.clone(),
            endpoint: "vpn.frankfurt.com:443".into(),
            subject: None,
            pin: "pin-sha256:pinned123=".into(),
            reason: "untrusted".into(),
        });

        // Accept with 'a'
        app.handle_key(crossterm::event::KeyCode::Char('a'))
            .await
            .unwrap();

        // Modal closed and profile updated with --servercert pin
        assert_eq!(app.active_modal, ActiveModal::None);
        let updated = app.profiles.iter().find(|p| p.id == prof_id).unwrap();
        assert!(
            updated
                .flags
                .contains(&"--servercert=pin-sha256:pinned123=".to_string())
        );

        // Also persisted in storage
        let from_storage = app
            .storage
            .load_profiles(None)
            .unwrap()
            .into_iter()
            .find(|p| p.id == prof_id)
            .unwrap();
        assert!(
            from_storage
                .flags
                .contains(&"--servercert=pin-sha256:pinned123=".to_string())
        );

        // Connection successfully established
        assert!(app.connection_state.can_disconnect());
        assert!(
            app.runner
                .is_connected
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn test_app_poll_log_events() {
        let mut app = setup_app();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        app.event_tx = Some(tx.clone());
        app.event_rx = Some(rx);

        tx.send(LogEvent::Stdout("Test stdout line".into()))
            .unwrap();
        tx.send(LogEvent::Stderr("Test stderr line".into()))
            .unwrap();
        tx.send(LogEvent::StatusChange("Connecting".into()))
            .unwrap();

        app.poll_log_events();

        assert!(app.logs.iter().any(|l| l.contains("Test stdout line")));
        assert!(app.logs.iter().any(|l| l.contains("Test stderr line")));
        assert!(app.logs.iter().any(|l| l.contains("Connecting")));
    }

    #[tokio::test]
    async fn test_app_execute_connect_preserves_event_rx_and_streams_logs() {
        let mut app = setup_app();
        let prof = app.profiles[0].clone();

        app.execute_connect(prof, None).await.unwrap();

        // event_rx and event_tx are retained
        assert!(app.event_rx.is_some());
        assert!(app.event_tx.is_some());

        // Asynchronously sending more events succeeds (channel is not dropped)
        let tx = app.event_tx.as_ref().unwrap();
        assert!(
            tx.send(LogEvent::Stdout("Async post-connect line".into()))
                .is_ok()
        );

        app.poll_log_events();
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Async post-connect line"))
        );
    }

    #[tokio::test]
    async fn test_app_execute_connect_resolves_profile_account_credentials() {
        let mut storage = InMemoryStorage::new();
        let acc1 = Account::new("Default Account");
        storage.save_account(&acc1).unwrap();

        let mut acc2 = Account::new("Linked Account");
        acc2.credentials = Some(crate::domain::account::Credentials {
            username: Some("linked_user".into()),
            password: Some("secret123".into()),
            auth_group: Some("staff".into()),
            cert_path: None,
            token: None,
        });
        storage.save_account(&acc2).unwrap();

        let prof =
            Profile::new_openconnect("Work", "vpn.work.com:443").with_account(acc2.id.clone());
        storage.save_profile(&prof).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        // Highlighted account is acc1 (index 0)
        assert_eq!(app.selected_account_idx, 0);

        app.execute_connect(prof, None).await.unwrap();

        assert_eq!(app.active_profile_name.as_deref(), Some("Work"));
        assert!(app.connection_state.can_disconnect());
    }

    #[tokio::test]
    async fn test_app_process_exited_and_disconnect_cleans_up_channels() {
        let mut app = setup_app();
        let prof = app.profiles[0].clone();

        app.execute_connect(prof, None).await.unwrap();
        assert!(app.event_rx.is_some());
        assert!(app.event_tx.is_some());

        // Process exit cleans up event_rx and event_tx
        app.handle_log_event(LogEvent::ProcessExited(1));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Failed { .. }
        ));
        assert!(app.event_rx.is_none());
        assert!(app.event_tx.is_none());

        // Reconnect and test disconnect cleanup
        let prof2 = app.profiles[0].clone();
        app.execute_connect(prof2, None).await.unwrap();
        assert!(app.event_rx.is_some());

        app.disconnect().await.unwrap();
        assert_eq!(app.connection_state, ConnectionState::Disconnected);
        assert!(app.event_rx.is_none());
        assert!(app.event_tx.is_none());
    }
}

#[cfg(test)]
pub mod config_edit_init {
    use super::tests::*;
    #[test]
    fn test_init() {
        test_app_config_edit_init();
    }
}

#[cfg(test)]
pub mod account_edit {
    use super::tests::*;
    #[test]
    fn test_edit() {
        test_app_account_edit();
    }
}

#[cfg(test)]
pub mod edit_hotkey {
    use super::tests::*;
    #[test]
    fn test_hotkey() {
        test_app_edit_hotkey();
    }
}

#[cfg(test)]
pub mod delete_flow {
    use super::tests::*;
    #[test]
    fn test_flow() {
        test_app_delete_flow();
    }
}
