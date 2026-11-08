use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, SslPolicy, VpnProtocol};
use crate::domain::state::{CertWarningState, ConnectionState, LatencyState};
use crate::infra::net_monitor::NetStats;
use crate::ports::pinger::Pinger;
use crate::ports::storage::ConfigStorage;
use crate::ports::vpn_runner::{CertProbeResult, LogEvent, VpnRunner};
use anyhow::Result;
use ratatui::widgets::ListState;
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

pub fn build_folder_options(folders: &[String]) -> Vec<String> {
    let mut opts = vec!["(None / Root)".to_string()];
    let mut sorted = folders.to_vec();
    sorted.sort();
    sorted.dedup();
    for f in sorted {
        let trimmed = f.trim().trim_matches('/');
        if !trimmed.is_empty() && !opts.iter().any(|o| o == trimmed) {
            opts.push(trimmed.to_string());
        }
    }
    opts.push("[+ New Folder]".to_string());
    opts
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAdderState {
    pub editing_profile_id: Option<ProfileId>,
    pub protocol: VpnProtocol,
    pub account_idx: Option<usize>,
    pub field_idx: usize,
    pub group: String,
    pub folder_options: Vec<String>,
    pub folder_option_idx: usize,
    pub custom_group_input: String,

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
        Self::new_with_folders(default_account, &[])
    }

    pub fn new_with_folders(default_account: Option<usize>, existing_folders: &[String]) -> Self {
        let folder_options = build_folder_options(existing_folders);
        Self {
            editing_profile_id: None,
            protocol: VpnProtocol::OpenConnect,
            account_idx: default_account,
            field_idx: 0,
            group: String::new(),
            folder_options,
            folder_option_idx: 0,
            custom_group_input: String::new(),

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
        Self::from_profile_with_folders(profile, accounts, &[])
    }

    pub fn from_profile_with_folders(
        profile: &Profile,
        accounts: &[Account],
        existing_folders: &[String],
    ) -> Self {
        let account_idx = profile
            .account_id
            .as_ref()
            .and_then(|id| accounts.iter().position(|a| a.id == *id));

        let mut state = Self::new_with_folders(account_idx, existing_folders);
        state.editing_profile_id = Some(profile.id.clone());
        state.protocol = profile.protocol;
        state.ssl_policy = profile.ssl_policy;
        state.group = profile.group.clone().unwrap_or_default();

        if let Some(ref g) = profile.group {
            let g_trimmed = g.trim().trim_matches('/');
            if let Some(pos) = state.folder_options.iter().position(|f| f == g_trimmed) {
                state.folder_option_idx = pos;
            } else {
                state.folder_option_idx = state.folder_options.len().saturating_sub(1);
                state.custom_group_input = g.clone();
            }
        } else {
            state.folder_option_idx = 0;
        }

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
            VpnProtocol::OpenConnect => 11,
            VpnProtocol::OpenVpn => 9,
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

    pub fn next_folder_option(&mut self) {
        if !self.folder_options.is_empty() {
            self.folder_option_idx = (self.folder_option_idx + 1) % self.folder_options.len();
            self.sync_group_from_selection();
        }
    }

    pub fn prev_folder_option(&mut self) {
        if !self.folder_options.is_empty() {
            if self.folder_option_idx == 0 {
                self.folder_option_idx = self.folder_options.len() - 1;
            } else {
                self.folder_option_idx -= 1;
            }
            self.sync_group_from_selection();
        }
    }

    pub fn is_on_new_folder(&self) -> bool {
        self.folder_option_idx + 1 == self.folder_options.len()
    }

    pub fn selected_folder_display(&self) -> &str {
        self.folder_options
            .get(self.folder_option_idx)
            .map(|s| s.as_str())
            .unwrap_or("(None / Root)")
    }

    pub fn sync_group_from_selection(&mut self) {
        let last_idx = self.folder_options.len().saturating_sub(1);
        if self.folder_option_idx == 0 {
            self.group.clear();
        } else if self.folder_option_idx == last_idx {
            self.group = self.custom_group_input.clone();
        } else if let Some(opt) = self.folder_options.get(self.folder_option_idx) {
            self.group = opt.clone();
        }
    }

    pub fn resolved_group(&self) -> Option<String> {
        let last_idx = self.folder_options.len().saturating_sub(1);
        if self.folder_option_idx == 0 {
            None
        } else if self.folder_option_idx == last_idx {
            let trimmed = self.custom_group_input.trim().trim_matches('/').to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        } else {
            self.folder_options
                .get(self.folder_option_idx)
                .map(|s| s.trim().trim_matches('/').to_string())
                .filter(|s| !s.is_empty())
        }
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
    Folder {
        path: String,
        profile_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncManagerState {
    pub selected_method_idx: usize,
    pub target_account_idx: usize,
    pub with_cisco: bool,
    pub status_message: Option<String>,
    pub error_message: Option<String>,
}

impl Default for SyncManagerState {
    fn default() -> Self {
        Self {
            selected_method_idx: 0,
            target_account_idx: 0,
            with_cisco: true,
            status_message: None,
            error_message: None,
        }
    }
}

impl SyncManagerState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchInputState {
    pub text: String,
    pub target_account_idx: usize,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NewFolderModalState {
    pub input: String,
    pub error_msg: Option<String>,
}

impl NewFolderModalState {
    pub fn new() -> Self {
        Self::default()
    }
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
    NewFolder(NewFolderModalState),
    FileBrowser {
        state: crate::ui::file_picker::FileBrowserState,
        parent_adder: ConfigAdderState,
    },
    SyncFileBrowser {
        state: crate::ui::file_picker::FileBrowserState,
        sync_state: SyncManagerState,
    },
    ConfirmDelete {
        target: DeleteTarget,
    },
    CertWarning(CertWarningState),
    SyncManager(SyncManagerState),
    BatchInput(BatchInputState),
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
    pub logs_zoomed: bool,
    pub configs_zoomed: bool,
    pub accounts_expanded: bool,
    pub expanded_folders: std::collections::HashSet<String>,
    pub custom_folders: Vec<String>,
    pub selected_tree_idx: usize,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
    pub profiles_list_state: ListState,
    pub accounts_list_state: ListState,
    pub logs_scroll_offset: usize,
    pub logs_auto_scroll: bool,
}

impl<S: ConfigStorage, R: VpnRunner, P: Pinger> App<S, R, P> {
    pub fn new(storage: S, runner: R, pinger: P) -> Self {
        let accounts = storage.load_accounts().unwrap_or_default();
        let profiles = storage.load_profiles(None).unwrap_or_default();
        let custom_folders = storage.load_folders().unwrap_or_default();

        let mut expanded_folders = std::collections::HashSet::new();
        for p in &profiles {
            if let Some(ref g) = p.group {
                let mut acc = String::new();
                for seg in g.split('/') {
                    let seg = seg.trim();
                    if !seg.is_empty() {
                        if !acc.is_empty() {
                            acc.push('/');
                        }
                        acc.push_str(seg);
                        expanded_folders.insert(acc.clone());
                    }
                }
            }
        }
        for f in &custom_folders {
            let mut acc = String::new();
            for seg in f.split('/') {
                let seg = seg.trim();
                if !seg.is_empty() {
                    if !acc.is_empty() {
                        acc.push('/');
                    }
                    acc.push_str(seg);
                    expanded_folders.insert(acc.clone());
                }
            }
        }

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
            logs_zoomed: false,
            configs_zoomed: false,
            accounts_expanded: false,
            expanded_folders,
            custom_folders,
            selected_tree_idx: 0,
            rx_history: Vec::new(),
            tx_history: Vec::new(),
            profiles_list_state: ListState::default(),
            accounts_list_state: ListState::default(),
            logs_scroll_offset: 0,
            logs_auto_scroll: true,
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

    pub fn update_net_stats(&mut self, stats: Option<NetStats>) {
        if let Some(s) = &stats {
            self.rx_history.push(s.rx_bytes_per_sec as u64);
            if self.rx_history.len() > 60 {
                self.rx_history.remove(0);
            }
            self.tx_history.push(s.tx_bytes_per_sec as u64);
            if self.tx_history.len() > 60 {
                self.tx_history.remove(0);
            }
        } else {
            self.rx_history.clear();
            self.tx_history.clear();
        }
        self.net_stats = stats;
    }

    pub fn reload_profiles(&mut self) {
        self.profiles = self.storage.load_profiles(None).unwrap_or_default();
        self.custom_folders = self.storage.load_folders().unwrap_or_default();
        if self.selected_profile_idx >= self.profiles.len() && !self.profiles.is_empty() {
            self.selected_profile_idx = self.profiles.len() - 1;
        }
        let tree = self.visible_tree();
        if self.selected_tree_idx >= tree.len() && !tree.is_empty() {
            self.selected_tree_idx = tree.len() - 1;
        }
    }

    pub fn ensure_custom_folder(&mut self, folder: &str) {
        let trimmed = folder.trim().trim_matches('/');
        if !trimmed.is_empty() && !self.custom_folders.iter().any(|f| f == trimmed) {
            self.custom_folders.push(trimmed.to_string());
            self.custom_folders.sort();
            let _ = self.storage.save_folders(&self.custom_folders);
        }
    }

    pub fn all_folders(&self) -> Vec<String> {
        let mut folders = self.custom_folders.clone();
        for p in &self.profiles {
            if let Some(ref g) = p.group {
                let trimmed = g.trim().trim_matches('/');
                if !trimmed.is_empty() && !folders.iter().any(|f| f == trimmed) {
                    folders.push(trimmed.to_string());
                }
            }
        }
        folders.sort();
        folders.dedup();
        folders
    }

    pub fn visible_tree(&self) -> Vec<crate::ui::tree::VisibleTreeNode> {
        crate::ui::tree::build_visible_tree(
            &self.profiles,
            &self.expanded_folders,
            &self.custom_folders,
        )
    }

    pub fn selected_tree_node(&self) -> Option<crate::ui::tree::VisibleTreeNode> {
        let tree = self.visible_tree();
        tree.get(self.selected_tree_idx).cloned()
    }

    pub fn sync_tree_selection(&mut self) {
        let tree = self.visible_tree();
        if let Some(pos) = tree.iter().position(|node| {
            if let crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. } = node {
                *profile_idx == self.selected_profile_idx
            } else {
                false
            }
        }) {
            self.selected_tree_idx = pos;
        } else if self.selected_tree_idx >= tree.len() && !tree.is_empty() {
            self.selected_tree_idx = tree.len() - 1;
        }
    }

    pub fn select_profile_by_idx(&mut self, idx: usize) {
        self.selected_profile_idx = idx;
        self.sync_tree_selection();
    }

    pub fn selected_account(&self) -> Option<&Account> {
        self.accounts.get(self.selected_account_idx)
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        let tree = self.visible_tree();
        if let Some(crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. }) =
            tree.get(self.selected_tree_idx)
        {
            return self.profiles.get(*profile_idx);
        }
        self.profiles.get(self.selected_profile_idx)
    }

    pub fn next_pane(&mut self) {
        self.active_pane = self.active_pane.next();
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = self.active_pane.prev();
    }

    pub fn select_next(&mut self) {
        if self.logs_zoomed {
            self.scroll_logs_down(1);
            return;
        }
        match self.active_pane {
            ActivePane::Accounts if !self.accounts.is_empty() => {
                self.selected_account_idx = (self.selected_account_idx + 1) % self.accounts.len();
                self.accounts_list_state
                    .select(Some(self.selected_account_idx));
            }
            ActivePane::Profiles if !self.profiles.is_empty() => {
                let tree = self.visible_tree();
                if !tree.is_empty() {
                    self.selected_tree_idx = (self.selected_tree_idx + 1) % tree.len();
                    self.profiles_list_state
                        .select(Some(self.selected_tree_idx));
                    if let Some(crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. }) =
                        tree.get(self.selected_tree_idx)
                    {
                        self.selected_profile_idx = *profile_idx;
                    }
                }
            }
            ActivePane::Logs => {
                self.scroll_logs_down(1);
            }
            _ => {}
        }
    }

    pub fn select_prev(&mut self) {
        if self.logs_zoomed {
            self.scroll_logs_up(1);
            return;
        }
        match self.active_pane {
            ActivePane::Accounts if !self.accounts.is_empty() => {
                if self.selected_account_idx == 0 {
                    self.selected_account_idx = self.accounts.len() - 1;
                } else {
                    self.selected_account_idx -= 1;
                }
                self.accounts_list_state
                    .select(Some(self.selected_account_idx));
            }
            ActivePane::Profiles if !self.profiles.is_empty() => {
                let tree = self.visible_tree();
                if !tree.is_empty() {
                    if self.selected_tree_idx == 0 {
                        self.selected_tree_idx = tree.len() - 1;
                    } else {
                        self.selected_tree_idx -= 1;
                    }
                    self.profiles_list_state
                        .select(Some(self.selected_tree_idx));
                    if let Some(crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. }) =
                        tree.get(self.selected_tree_idx)
                    {
                        self.selected_profile_idx = *profile_idx;
                    }
                }
            }
            ActivePane::Logs => {
                self.scroll_logs_up(1);
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
        if self.logs_auto_scroll {
            self.logs_scroll_offset = 0;
        }
    }

    pub fn scroll_logs_up(&mut self, lines: usize) {
        let max_offset = self.logs.len().saturating_sub(1);
        self.logs_scroll_offset = (self.logs_scroll_offset + lines).min(max_offset);
        self.logs_auto_scroll = false;
    }

    pub fn scroll_logs_down(&mut self, lines: usize) {
        if self.logs_scroll_offset <= lines {
            self.logs_scroll_offset = 0;
            self.logs_auto_scroll = true;
        } else {
            self.logs_scroll_offset -= lines;
        }
    }

    pub fn scroll_logs_to_top(&mut self) {
        self.logs_scroll_offset = self.logs.len().saturating_sub(1);
        self.logs_auto_scroll = false;
    }

    pub fn scroll_logs_to_bottom(&mut self) {
        self.logs_scroll_offset = 0;
        self.logs_auto_scroll = true;
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
                            10 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.push(' ');
                                    adder.group.push(' ');
                                } else {
                                    adder.next_folder_option();
                                }
                            }
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
                            8 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.push(' ');
                                    adder.group.push(' ');
                                } else {
                                    adder.next_folder_option();
                                }
                            }
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
                            10 => {
                                adder.prev_folder_option();
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
                            8 => {
                                adder.prev_folder_option();
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
                            10 => {
                                adder.next_folder_option();
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
                            8 => {
                                adder.next_folder_option();
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
                            10 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.pop();
                                    adder.group.pop();
                                } else {
                                    adder.folder_option_idx = 0;
                                    adder.sync_group_from_selection();
                                }
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
                            8 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.pop();
                                    adder.group.pop();
                                } else {
                                    adder.folder_option_idx = 0;
                                    adder.sync_group_from_selection();
                                }
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
                            10 => {
                                if !adder.is_on_new_folder() {
                                    adder.folder_option_idx =
                                        adder.folder_options.len().saturating_sub(1);
                                    adder.custom_group_input.clear();
                                    adder.group.clear();
                                }
                                adder.custom_group_input.push(c);
                                adder.group.push(c);
                            }
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            2 => adder.ovpn_name.push(c),
                            3 => adder.ovpn_path.push(c),
                            4 => adder.ovpn_remote.push(c),
                            7 => adder.ovpn_custom_flags.push(c),
                            8 => {
                                if !adder.is_on_new_folder() {
                                    adder.folder_option_idx =
                                        adder.folder_options.len().saturating_sub(1);
                                    adder.custom_group_input.clear();
                                    adder.group.clear();
                                }
                                adder.custom_group_input.push(c);
                                adder.group.push(c);
                            }
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

            ActiveModal::NewFolder(mut state) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Char(c) => {
                    state.input.push(c);
                    state.error_msg = None;
                    self.active_modal = ActiveModal::NewFolder(state);
                }
                KeyCode::Backspace => {
                    state.input.pop();
                    state.error_msg = None;
                    self.active_modal = ActiveModal::NewFolder(state);
                }
                KeyCode::Enter => {
                    let trimmed = state.input.trim().trim_matches('/').to_string();
                    if trimmed.is_empty() {
                        state.error_msg = Some("Folder name cannot be empty".to_string());
                        self.active_modal = ActiveModal::NewFolder(state);
                    } else {
                        if !self.custom_folders.contains(&trimmed) {
                            self.custom_folders.push(trimmed.clone());
                            self.custom_folders.sort();
                            let _ = self.storage.save_folders(&self.custom_folders);
                        }
                        let mut acc = String::new();
                        for seg in trimmed.split('/') {
                            let seg = seg.trim();
                            if !seg.is_empty() {
                                if !acc.is_empty() {
                                    acc.push('/');
                                }
                                acc.push_str(seg);
                                self.expanded_folders.insert(acc.clone());
                            }
                        }
                        self.sync_tree_selection();
                        self.active_modal = ActiveModal::None;
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::NewFolder(state);
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
                        DeleteTarget::Folder {
                            path,
                            profile_count,
                        } => {
                            let prefix = format!("{}/", path);
                            // 1. Identify all profile IDs matching this folder or any subfolder
                            let matching_ids: Vec<crate::domain::config::ProfileId> = self
                                .profiles
                                .iter()
                                .filter(|p| {
                                    if let Some(ref g) = p.group {
                                        g == &path || g.starts_with(&prefix)
                                    } else {
                                        false
                                    }
                                })
                                .map(|p| p.id.clone())
                                .collect();

                            // 2. Delete each profile from storage
                            for id in &matching_ids {
                                let _ = self.storage.delete_profile(id);
                            }

                            // 3. Remove from self.profiles
                            self.profiles.retain(|p| !matching_ids.contains(&p.id));

                            // 4. Remove this folder and all subfolders from custom_folders
                            self.custom_folders
                                .retain(|f| f != &path && !f.starts_with(&prefix));
                            let _ = self.storage.save_folders(&self.custom_folders);

                            // 5. Clean up expanded_folders
                            self.expanded_folders
                                .retain(|f| f != &path && !f.starts_with(&prefix));

                            // 6. Clamp selected_tree_idx
                            let tree_len = self.visible_tree().len();
                            if self.selected_tree_idx >= tree_len && tree_len > 0 {
                                self.selected_tree_idx = tree_len - 1;
                            }

                            // 7. Log
                            if profile_count == 0 {
                                self.add_log(format!("Deleted empty folder '{}'", path));
                            } else {
                                self.add_log(format!(
                                    "Deleted folder '{}' and {} profile(s)",
                                    path, profile_count
                                ));
                            }
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
            ActiveModal::SyncManager(mut state) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    state.selected_method_idx = state.selected_method_idx.saturating_sub(1);
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if state.selected_method_idx < 2 {
                        state.selected_method_idx += 1;
                    }
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Tab => {
                    if !self.accounts.is_empty() {
                        state.target_account_idx =
                            (state.target_account_idx + 1) % self.accounts.len();
                    }
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Char(' ') => {
                    state.with_cisco = !state.with_cisco;
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Enter => match state.selected_method_idx {
                    0 => {
                        let account = self.accounts.get(state.target_account_idx);
                        let (username, password) = match account {
                            Some(acc) => {
                                let creds = acc.credentials.as_ref();
                                let u = creds.and_then(|c| c.username.clone()).unwrap_or_default();
                                let p = creds.and_then(|c| c.password.clone()).unwrap_or_default();
                                if u.trim().is_empty() || p.trim().is_empty() {
                                    state.error_message = Some(format!(
                                        "Account '{}' has empty username or password.",
                                        acc.id.0
                                    ));
                                    self.active_modal = ActiveModal::SyncManager(state);
                                    return Ok(());
                                }
                                (u, p)
                            }
                            None => {
                                state.error_message =
                                    Some("No account selected for sync.".to_string());
                                self.active_modal = ActiveModal::SyncManager(state);
                                return Ok(());
                            }
                        };
                        let target_acc_id = account.map(|a| a.id.clone());

                        let client =
                            match crate::infra::biovpn_client::ReqwestBioVpnClient::new(None) {
                                Ok(c) => c,
                                Err(e) => {
                                    state.error_message = Some(format!("HTTP client error: {}", e));
                                    self.active_modal = ActiveModal::SyncManager(state);
                                    return Ok(());
                                }
                            };

                        use crate::ports::biovpn::BioVpnClient;
                        match client.fetch_bundle(&username, &password).await {
                            Ok(zip_bytes) => {
                                let dest = {
                                    let root = self.storage.get_config_root();
                                    if root.starts_with("/mock") {
                                        std::env::temp_dir().join("vpn_tui_test_openvpn")
                                    } else {
                                        root.join("openvpn")
                                    }
                                };
                                let cursor = std::io::Cursor::new(zip_bytes);
                                match crate::domain::importer::ProfileImporter::import_zip(
                                    cursor,
                                    &dest,
                                    target_acc_id,
                                    state.with_cisco,
                                ) {
                                    Ok(summary) => {
                                        for prof in summary.profiles {
                                            let _ = self.storage.save_profile(&prof);
                                        }
                                        if summary.openvpn_count > 0 {
                                            self.ensure_custom_folder("BioVPN/OpenVPN");
                                        }
                                        if summary.openconnect_count > 0 {
                                            self.ensure_custom_folder("BioVPN/Cisco");
                                        }
                                        self.reload_profiles();
                                        self.expanded_folders.insert("BioVPN".to_string());
                                        self.expanded_folders.insert("BioVPN/Cisco".to_string());
                                        self.expanded_folders.insert("BioVPN/OpenVPN".to_string());
                                        self.add_log(format!(
                                            "BioVPN sync completed: imported {} OpenVPN and {} Cisco profiles.",
                                            summary.openvpn_count, summary.openconnect_count
                                        ));
                                        self.active_modal = ActiveModal::None;
                                    }
                                    Err(e) => {
                                        state.error_message =
                                            Some(format!("Bundle extraction error: {}", e));
                                        self.active_modal = ActiveModal::SyncManager(state);
                                    }
                                }
                            }
                            Err(e) => {
                                state.error_message = Some(format!("Sync error: {}", e));
                                self.active_modal = ActiveModal::SyncManager(state);
                            }
                        }
                    }
                    1 => {
                        self.active_modal = ActiveModal::SyncFileBrowser {
                            state: crate::ui::file_picker::FileBrowserState::new(None),
                            sync_state: state,
                        };
                    }
                    2 => {
                        self.active_modal = ActiveModal::BatchInput(BatchInputState {
                            text: String::new(),
                            target_account_idx: state.target_account_idx,
                            error_message: None,
                        });
                    }
                    _ => {
                        self.active_modal = ActiveModal::SyncManager(state);
                    }
                },
                _ => {
                    self.active_modal = ActiveModal::SyncManager(state);
                }
            },
            ActiveModal::SyncFileBrowser {
                mut state,
                sync_state,
            } => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::SyncManager(sync_state);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state.select_next();
                    self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    state.select_prev();
                    self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                }
                KeyCode::Backspace | KeyCode::Left => {
                    state.go_up();
                    self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                }
                KeyCode::Enter => {
                    if let Some(selected_file) = state.enter_selected() {
                        let is_zip = selected_file
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(|s| s.eq_ignore_ascii_case("zip"))
                            .unwrap_or(false);
                        if is_zip {
                            let target_acc = self
                                .accounts
                                .get(sync_state.target_account_idx)
                                .map(|a| a.id.clone());
                            let dest = {
                                let root = self.storage.get_config_root();
                                if root.starts_with("/mock") {
                                    std::env::temp_dir().join("vpn_tui_test_openvpn")
                                } else {
                                    root.join("openvpn")
                                }
                            };
                            match std::fs::File::open(&selected_file) {
                                Ok(file) => {
                                    match crate::domain::importer::ProfileImporter::import_zip(
                                        file,
                                        &dest,
                                        target_acc,
                                        sync_state.with_cisco,
                                    ) {
                                        Ok(summary) => {
                                            for prof in summary.profiles {
                                                let _ = self.storage.save_profile(&prof);
                                            }
                                            if summary.openvpn_count > 0 {
                                                self.ensure_custom_folder("BioVPN/OpenVPN");
                                            }
                                            if summary.openconnect_count > 0 {
                                                self.ensure_custom_folder("BioVPN/Cisco");
                                            }
                                            self.reload_profiles();
                                            self.expanded_folders.insert("BioVPN".to_string());
                                            self.expanded_folders
                                                .insert("BioVPN/Cisco".to_string());
                                            self.expanded_folders
                                                .insert("BioVPN/OpenVPN".to_string());
                                            self.add_log(format!(
                                                "Imported {} OpenVPN and {} Cisco profiles from archive.",
                                                summary.openvpn_count, summary.openconnect_count
                                            ));
                                            self.active_modal = ActiveModal::None;
                                        }
                                        Err(e) => {
                                            let mut sync = sync_state;
                                            sync.error_message = Some(format!("ZIP error: {}", e));
                                            self.active_modal = ActiveModal::SyncManager(sync);
                                        }
                                    }
                                }
                                Err(e) => {
                                    let mut sync = sync_state;
                                    sync.error_message =
                                        Some(format!("Could not open file: {}", e));
                                    self.active_modal = ActiveModal::SyncManager(sync);
                                }
                            }
                        } else {
                            self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                        }
                    } else {
                        self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::SyncFileBrowser { state, sync_state };
                }
            },
            ActiveModal::BatchInput(mut state) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::SyncManager(SyncManagerState {
                        target_account_idx: state.target_account_idx,
                        ..Default::default()
                    });
                }
                KeyCode::Backspace => {
                    state.text.pop();
                    self.active_modal = ActiveModal::BatchInput(state);
                }
                KeyCode::Char(c) => {
                    state.text.push(c);
                    self.active_modal = ActiveModal::BatchInput(state);
                }
                KeyCode::Enter => {
                    let target_acc = self
                        .accounts
                        .get(state.target_account_idx)
                        .map(|a| a.id.clone());
                    match crate::domain::importer::ProfileImporter::parse_server_list(
                        &state.text,
                        target_acc,
                    ) {
                        Ok(profiles) if !profiles.is_empty() => {
                            let count = profiles.len();
                            for prof in profiles {
                                let _ = self.storage.save_profile(&prof);
                            }
                            self.reload_profiles();
                            self.add_log(format!(
                                "Successfully batch imported {} server profiles.",
                                count
                            ));
                            self.active_modal = ActiveModal::None;
                        }
                        Ok(_) => {
                            state.error_message = Some(
                                "No valid server entries found. Format: <Name> <IP:Port>".into(),
                            );
                            self.active_modal = ActiveModal::BatchInput(state);
                        }
                        Err(e) => {
                            state.error_message = Some(e.to_string());
                            self.active_modal = ActiveModal::BatchInput(state);
                        }
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::BatchInput(state);
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
                KeyCode::Enter => match self.active_pane {
                    ActivePane::Profiles => {
                        let tree = self.visible_tree();
                        if let Some(node) = tree.get(self.selected_tree_idx) {
                            match node {
                                crate::ui::tree::VisibleTreeNode::Folder { path, .. } => {
                                    if self.expanded_folders.contains(path) {
                                        self.expanded_folders.remove(path);
                                    } else {
                                        self.expanded_folders.insert(path.clone());
                                    }
                                }
                                crate::ui::tree::VisibleTreeNode::Profile {
                                    profile_idx, ..
                                } => {
                                    self.selected_profile_idx = *profile_idx;
                                    self.connect_current().await?;
                                }
                            }
                        } else {
                            self.connect_current().await?;
                        }
                    }
                    ActivePane::Accounts => {
                        if !self.accounts_expanded {
                            self.accounts_expanded = true;
                        } else if let Some(acc) = self.selected_account() {
                            self.active_modal =
                                ActiveModal::Account(AccountModalState::from_account(acc));
                        }
                    }
                    _ => {}
                },
                KeyCode::Char(' ') => match self.active_pane {
                    ActivePane::Accounts => {
                        self.accounts_expanded = !self.accounts_expanded;
                    }
                    ActivePane::Profiles => {
                        let tree = self.visible_tree();
                        if let Some(crate::ui::tree::VisibleTreeNode::Folder { path, .. }) =
                            tree.get(self.selected_tree_idx)
                        {
                            if self.expanded_folders.contains(path) {
                                self.expanded_folders.remove(path);
                            } else {
                                self.expanded_folders.insert(path.clone());
                            }
                        }
                    }
                    _ => {}
                },
                KeyCode::Right if self.active_pane == ActivePane::Profiles => {
                    let tree = self.visible_tree();
                    if let Some(crate::ui::tree::VisibleTreeNode::Folder {
                        path, expanded, ..
                    }) = tree.get(self.selected_tree_idx)
                    {
                        if !expanded {
                            self.expanded_folders.insert(path.clone());
                        } else if self.selected_tree_idx + 1 < tree.len() {
                            self.selected_tree_idx += 1;
                            if let Some(crate::ui::tree::VisibleTreeNode::Profile {
                                profile_idx,
                                ..
                            }) = tree.get(self.selected_tree_idx)
                            {
                                self.selected_profile_idx = *profile_idx;
                            }
                        }
                    }
                }
                KeyCode::Left if self.active_pane == ActivePane::Profiles => {
                    let tree = self.visible_tree();
                    if let Some(node) = tree.get(self.selected_tree_idx) {
                        match node {
                            crate::ui::tree::VisibleTreeNode::Folder {
                                path,
                                expanded,
                                depth,
                                ..
                            } => {
                                if *expanded {
                                    self.expanded_folders.remove(path);
                                } else if *depth > 0 {
                                    let target_depth = depth - 1;
                                    for i in (0..self.selected_tree_idx).rev() {
                                        if let crate::ui::tree::VisibleTreeNode::Folder {
                                            depth: d,
                                            ..
                                        } = &tree[i]
                                            && *d == target_depth
                                        {
                                            self.selected_tree_idx = i;
                                            break;
                                        }
                                    }
                                }
                            }
                            crate::ui::tree::VisibleTreeNode::Profile { depth, .. } => {
                                if *depth > 0 {
                                    let target_depth = depth - 1;
                                    for i in (0..self.selected_tree_idx).rev() {
                                        if let crate::ui::tree::VisibleTreeNode::Folder {
                                            depth: d,
                                            ..
                                        } = &tree[i]
                                            && *d == target_depth
                                        {
                                            self.selected_tree_idx = i;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                KeyCode::PageDown => {
                    if self.logs_zoomed {
                        self.scroll_logs_down(10);
                    } else {
                        match self.active_pane {
                            ActivePane::Profiles => {
                                let tree = self.visible_tree();
                                if !tree.is_empty() {
                                    self.selected_tree_idx =
                                        (self.selected_tree_idx + 10).min(tree.len() - 1);
                                    self.profiles_list_state
                                        .select(Some(self.selected_tree_idx));
                                    if let Some(crate::ui::tree::VisibleTreeNode::Profile {
                                        profile_idx,
                                        ..
                                    }) = tree.get(self.selected_tree_idx)
                                    {
                                        self.selected_profile_idx = *profile_idx;
                                    }
                                }
                            }
                            ActivePane::Accounts
                                if self.accounts_expanded && !self.accounts.is_empty() =>
                            {
                                self.selected_account_idx =
                                    (self.selected_account_idx + 5).min(self.accounts.len() - 1);
                                self.accounts_list_state
                                    .select(Some(self.selected_account_idx));
                            }
                            ActivePane::Logs => {
                                self.scroll_logs_down(10);
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::PageUp => {
                    if self.logs_zoomed {
                        self.scroll_logs_up(10);
                    } else {
                        match self.active_pane {
                            ActivePane::Profiles => {
                                let tree = self.visible_tree();
                                if !tree.is_empty() {
                                    self.selected_tree_idx =
                                        self.selected_tree_idx.saturating_sub(10);
                                    self.profiles_list_state
                                        .select(Some(self.selected_tree_idx));
                                    if let Some(crate::ui::tree::VisibleTreeNode::Profile {
                                        profile_idx,
                                        ..
                                    }) = tree.get(self.selected_tree_idx)
                                    {
                                        self.selected_profile_idx = *profile_idx;
                                    }
                                }
                            }
                            ActivePane::Accounts
                                if self.accounts_expanded && !self.accounts.is_empty() =>
                            {
                                self.selected_account_idx =
                                    self.selected_account_idx.saturating_sub(5);
                                self.accounts_list_state
                                    .select(Some(self.selected_account_idx));
                            }
                            ActivePane::Logs => {
                                self.scroll_logs_up(10);
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::Home => {
                    if self.logs_zoomed || self.active_pane == ActivePane::Logs {
                        self.scroll_logs_to_top();
                    } else {
                        match self.active_pane {
                            ActivePane::Profiles => {
                                self.selected_tree_idx = 0;
                                self.profiles_list_state.select(Some(0));
                                let tree = self.visible_tree();
                                if let Some(crate::ui::tree::VisibleTreeNode::Profile {
                                    profile_idx,
                                    ..
                                }) = tree.first()
                                {
                                    self.selected_profile_idx = *profile_idx;
                                }
                            }
                            ActivePane::Accounts
                                if self.accounts_expanded && !self.accounts.is_empty() =>
                            {
                                self.selected_account_idx = 0;
                                self.accounts_list_state.select(Some(0));
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::End => {
                    if self.logs_zoomed || self.active_pane == ActivePane::Logs {
                        self.scroll_logs_to_bottom();
                    } else {
                        match self.active_pane {
                            ActivePane::Profiles => {
                                let tree = self.visible_tree();
                                if !tree.is_empty() {
                                    self.selected_tree_idx = tree.len() - 1;
                                    self.profiles_list_state
                                        .select(Some(self.selected_tree_idx));
                                    if let Some(crate::ui::tree::VisibleTreeNode::Profile {
                                        profile_idx,
                                        ..
                                    }) = tree.last()
                                    {
                                        self.selected_profile_idx = *profile_idx;
                                    }
                                }
                            }
                            ActivePane::Accounts
                                if self.accounts_expanded && !self.accounts.is_empty() =>
                            {
                                self.selected_account_idx = self.accounts.len() - 1;
                                self.accounts_list_state
                                    .select(Some(self.selected_account_idx));
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::Char('g') if self.logs_zoomed || self.active_pane == ActivePane::Logs => {
                    self.scroll_logs_to_top();
                }
                KeyCode::Char('G') if self.logs_zoomed || self.active_pane == ActivePane::Logs => {
                    self.scroll_logs_to_bottom();
                }
                KeyCode::Char('C') | KeyCode::Char('c') => {
                    self.configs_zoomed = !self.configs_zoomed;
                }
                KeyCode::Char('d') => {
                    self.disconnect().await?;
                }
                KeyCode::Char('p') => {
                    self.ping_all().await;
                }
                KeyCode::Char('f') => {
                    self.logs_zoomed = !self.logs_zoomed;
                }
                KeyCode::Esc => {
                    if self.logs_zoomed {
                        self.logs_zoomed = false;
                    } else if self.configs_zoomed {
                        self.configs_zoomed = false;
                    } else if self.active_pane == ActivePane::Accounts {
                        if self.accounts_expanded {
                            self.accounts_expanded = false;
                        }
                        self.active_pane = ActivePane::Profiles;
                    }
                }
                KeyCode::Char('A') => {
                    self.accounts_expanded = !self.accounts_expanded;
                    if self.accounts_expanded {
                        self.active_pane = ActivePane::Accounts;
                    } else if self.active_pane == ActivePane::Accounts {
                        self.active_pane = ActivePane::Profiles;
                    }
                }
                KeyCode::Char('a') => {
                    self.active_modal = ActiveModal::Account(AccountModalState::new());
                }
                KeyCode::Char('S') | KeyCode::Char('s') => {
                    self.active_modal = ActiveModal::SyncManager(SyncManagerState::new());
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
                                    let folders = self.all_folders();
                                    self.active_modal = ActiveModal::ConfigAdder(
                                        ConfigAdderState::from_profile_with_folders(
                                            prof,
                                            &self.accounts,
                                            &folders,
                                        ),
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
                        let tree = self.visible_tree();
                        if let Some(crate::ui::tree::VisibleTreeNode::Folder {
                            path,
                            total_profiles,
                            ..
                        }) = tree.get(self.selected_tree_idx)
                        {
                            let path = path.clone();
                            let total_profiles = *total_profiles;
                            let prefix = format!("{}/", path);

                            let has_active_tunnel = (self.connection_state.is_connected()
                                || matches!(
                                    self.connection_state,
                                    ConnectionState::Connecting { .. }
                                ))
                                && self.profiles.iter().any(|p| {
                                    let in_folder = if let Some(ref g) = p.group {
                                        g == &path || g.starts_with(&prefix)
                                    } else {
                                        false
                                    };
                                    in_folder
                                        && self.active_profile_name.as_deref() == Some(&p.name)
                                });

                            if has_active_tunnel {
                                self.add_log(
                                    "Cannot delete folder containing an active connection. Please disconnect first.",
                                );
                            } else {
                                self.active_modal = ActiveModal::ConfirmDelete {
                                    target: DeleteTarget::Folder {
                                        path,
                                        profile_count: total_profiles,
                                    },
                                };
                            }
                        } else if let Some(prof) = self.selected_profile() {
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
                    let folders = self.all_folders();
                    self.active_modal = ActiveModal::ConfigAdder(
                        ConfigAdderState::new_with_folders(def_acc, &folders),
                    );
                }
                KeyCode::Char('m') | KeyCode::Char('M') => {
                    self.active_modal = ActiveModal::NewFolder(NewFolderModalState::new());
                }
                _ => {}
            },
        }

        Ok(())
    }

    pub fn submit_config_adder(&mut self, mut adder: ConfigAdderState) -> Result<()> {
        let group_opt = adder.resolved_group();
        if let Some(ref g) = group_opt
            && !self.custom_folders.contains(g)
        {
            self.custom_folders.push(g.clone());
            self.custom_folders.sort();
            let _ = self.storage.save_folders(&self.custom_folders);
        }

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
                prof.group = group_opt.clone();

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

                if let Some(ref g) = prof.group {
                    let mut acc = String::new();
                    for seg in g.split('/') {
                        let seg = seg.trim();
                        if !seg.is_empty() {
                            if !acc.is_empty() {
                                acc.push('/');
                            }
                            acc.push_str(seg);
                            self.expanded_folders.insert(acc.clone());
                        }
                    }
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
                            prof.group = group_opt.clone();
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
                            if let Some(ref g) = prof.group {
                                let mut acc = String::new();
                                for seg in g.split('/') {
                                    let seg = seg.trim();
                                    if !seg.is_empty() {
                                        if !acc.is_empty() {
                                            acc.push('/');
                                        }
                                        acc.push_str(seg);
                                        self.expanded_folders.insert(acc.clone());
                                    }
                                }
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
                    prof.group = group_opt.clone();
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
                    if let Some(ref g) = prof.group {
                        let mut acc = String::new();
                        for seg in g.split('/') {
                            let seg = seg.trim();
                            if !seg.is_empty() {
                                if !acc.is_empty() {
                                    acc.push('/');
                                }
                                acc.push_str(seg);
                                self.expanded_folders.insert(acc.clone());
                            }
                        }
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
    use crossterm::event::KeyCode;

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

    #[tokio::test]
    async fn test_app_tree_navigation_expand_collapse_and_connect() {
        use crossterm::event::KeyCode;

        let mut storage = InMemoryStorage::new();
        let p1 = Profile::new_openconnect("DE Munich", "1.1.1.1:443").with_group("BioVPN/Cisco");
        let p2 = Profile::new_openconnect("NL Amsterdam", "2.2.2.2:443").with_group("BioVPN/Cisco");
        storage.save_profile(&p1).unwrap();
        storage.save_profile(&p2).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        assert_eq!(app.active_pane, ActivePane::Profiles);

        // Initially folders are expanded: BioVPN (0), Cisco (1), DE Munich (2), NL Amsterdam (3)
        let tree = app.visible_tree();
        assert_eq!(tree.len(), 4);

        // Move cursor to BioVPN/Cisco (index 1)
        app.selected_tree_idx = 1;
        assert_eq!(tree[1].folder_path(), Some("BioVPN/Cisco"));

        // Press Space on Cisco folder -> Collapses Cisco
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        assert!(!app.expanded_folders.contains("BioVPN/Cisco"));
        let tree_collapsed = app.visible_tree();
        assert_eq!(tree_collapsed.len(), 2); // BioVPN, Cisco

        // Press Enter on Cisco folder -> Expands Cisco without connecting
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert!(app.expanded_folders.contains("BioVPN/Cisco"));
        assert!(!app.connection_state.is_connected());

        // Move cursor down to DE Munich (index 2)
        app.handle_key(KeyCode::Down).await.unwrap();
        assert_eq!(app.selected_tree_idx, 2);
        assert_eq!(app.selected_profile().unwrap().name, "DE Munich");

        // Press Enter on profile -> Connects!
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_profile_name.as_deref(), Some("DE Munich"));
        assert!(app.connection_state.can_disconnect());

        // Test Left arrow jumps to parent folder
        app.handle_key(KeyCode::Left).await.unwrap();
        assert_eq!(app.selected_tree_idx, 1); // Cisco folder
    }

    #[tokio::test]
    async fn test_config_adder_group_field_and_submit() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Open config adder with 'n'
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        let mut adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            _ => panic!("Expected ConfigAdder modal"),
        };

        // OpenConnect total_fields = 11
        assert_eq!(adder.total_fields(), 11);

        adder.oc_name = "Production US".to_string();
        adder.oc_endpoint = "vpn.us.corp:443".to_string();
        adder.field_idx = 10; // Group field

        app.active_modal = ActiveModal::ConfigAdder(adder);

        // Type group name: "Work/East"
        for c in "Work/East".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }

        // Hit Enter to submit
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // Check profile was saved with group
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "Production US");
        assert_eq!(app.profiles[0].group.as_deref(), Some("Work/East"));

        // Check folder hierarchy was automatically expanded
        assert!(app.expanded_folders.contains("Work"));
        assert!(app.expanded_folders.contains("Work/East"));
    }

    #[tokio::test]
    async fn test_app_new_folder_modal_flow() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'm' to open New Folder modal
        app.handle_key(KeyCode::Char('m')).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::NewFolder(_)));

        // Type folder path "Personal/Asia"
        for c in "Personal/Asia".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }

        // Press Enter to create
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // Verify folder is in custom_folders and saved to storage
        assert!(app.custom_folders.contains(&"Personal/Asia".to_string()));
        assert!(
            app.storage
                .load_folders()
                .unwrap()
                .contains(&"Personal/Asia".to_string())
        );

        // Verify folder path is expanded
        assert!(app.expanded_folders.contains("Personal"));
        assert!(app.expanded_folders.contains("Personal/Asia"));

        // Verify visible tree displays the empty folder with count 0
        let tree = app.visible_tree();
        assert_eq!(tree.len(), 2); // Personal (0) and Asia (0)
        assert_eq!(tree[0].folder_path(), Some("Personal"));
        assert_eq!(tree[1].folder_path(), Some("Personal/Asia"));
    }

    #[tokio::test]
    async fn test_config_adder_folder_selection_cycling_and_submit() {
        use crossterm::event::KeyCode;

        let mut storage = InMemoryStorage::new();
        storage
            .save_folders(&["Work/Europe".to_string(), "BioVPN/Cisco".to_string()])
            .unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'n' to open ConfigAdder
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            _ => panic!("Expected ConfigAdder modal"),
        };

        // Folders list: ["(None / Root)", "BioVPN/Cisco", "Work/Europe", "[+ New Folder]"]
        assert_eq!(adder.folder_options.len(), 4);
        assert_eq!(adder.folder_option_idx, 0); // initially (None / Root)

        // Set field_idx to 10 (Folder field)
        let mut adder = adder;
        adder.oc_name = "Frankfurt Gateway".to_string();
        adder.oc_endpoint = "1.2.3.4:443".to_string();
        adder.field_idx = 10;
        app.active_modal = ActiveModal::ConfigAdder(adder);

        // Press Space on field 10 -> Cycles to index 1: "BioVPN/Cisco"
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            _ => panic!("Expected ConfigAdder modal"),
        };
        assert_eq!(adder.folder_option_idx, 1);
        assert_eq!(adder.selected_folder_display(), "BioVPN/Cisco");

        // Press Right on field 10 -> Cycles to index 2: "Work/Europe"
        app.handle_key(KeyCode::Right).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            _ => panic!("Expected ConfigAdder modal"),
        };
        assert_eq!(adder.folder_option_idx, 2);
        assert_eq!(adder.selected_folder_display(), "Work/Europe");

        // Hit Enter to submit profile
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // Check profile was saved with group "Work/Europe"
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].group.as_deref(), Some("Work/Europe"));
    }

    #[tokio::test]
    async fn test_app_folder_delete_active_connection_guard() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let prof = Profile::new_openconnect("Work Server", "1.2.3.4:443").with_group("Work/Europe");
        app.storage.save_profile(&prof).unwrap();
        app.profiles = app.storage.load_profiles(None).unwrap();

        // Mark profile as connected
        app.connection_state = ConnectionState::Connected {
            interface: "tun0".into(),
            assigned_ip: Some("10.8.0.2".into()),
            connected_at_secs: 42,
        };
        app.active_profile_name = Some("Work Server".to_string());

        // Tree root index 0 is "Work"
        app.active_pane = ActivePane::Profiles;
        app.selected_tree_idx = 0;

        // Press 'x' on the Work folder node
        app.handle_key(KeyCode::Char('x')).await.unwrap();

        // Deletion must be blocked
        assert_eq!(app.active_modal, ActiveModal::None);
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Cannot delete folder containing an active connection"))
        );
    }

    #[tokio::test]
    async fn test_app_folder_delete_empty_folder_flow() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Add an empty folder
        app.custom_folders = vec!["Personal".to_string()];
        app.storage.save_folders(&app.custom_folders).unwrap();

        // Cursor on "Personal"
        app.active_pane = ActivePane::Profiles;
        app.selected_tree_idx = 0;

        // Press 'x' -> ConfirmDelete opens
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert_eq!(
            app.active_modal,
            ActiveModal::ConfirmDelete {
                target: DeleteTarget::Folder {
                    path: "Personal".to_string(),
                    profile_count: 0,
                }
            }
        );

        // Press 'n' to cancel
        app.handle_key(KeyCode::Char('n')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.custom_folders, vec!["Personal".to_string()]);

        // Reopen and confirm with 'y'
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        app.handle_key(KeyCode::Char('y')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert!(app.custom_folders.is_empty());
        assert!(app.storage.load_folders().unwrap().is_empty());
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Deleted empty folder 'Personal'"))
        );
    }

    #[tokio::test]
    async fn test_app_folder_delete_populated_cascade_flow() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let prof1 = Profile::new_openconnect("Munich", "1.1.1.1:443").with_group("Work/Europe");
        let prof2 = Profile::new_openconnect("Tokyo", "2.2.2.2:443").with_group("Work/Asia");
        let standalone = Profile::new_openvpn("Home", "3.3.3.3:1194", None);
        app.storage.save_profile(&prof1).unwrap();
        app.storage.save_profile(&prof2).unwrap();
        app.storage.save_profile(&standalone).unwrap();
        app.profiles = app.storage.load_profiles(None).unwrap();

        // Also add an empty subfolder under Work
        app.custom_folders = vec!["Work/Special".to_string(), "OtherFolder".to_string()];
        app.storage.save_folders(&app.custom_folders).unwrap();
        app.expanded_folders.insert("Work".to_string());
        app.expanded_folders.insert("Work/Europe".to_string());

        // Select "Work" folder
        app.active_pane = ActivePane::Profiles;
        let work_idx = app
            .visible_tree()
            .iter()
            .position(|n| {
                matches!(
                    n,
                    crate::ui::tree::VisibleTreeNode::Folder { path, .. } if path == "Work"
                )
            })
            .expect("Work folder should exist in tree");
        app.selected_tree_idx = work_idx;

        // Press 'x' -> ConfirmDelete opens with count 2
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert_eq!(
            app.active_modal,
            ActiveModal::ConfirmDelete {
                target: DeleteTarget::Folder {
                    path: "Work".to_string(),
                    profile_count: 2,
                }
            }
        );

        // Press Enter to confirm deletion
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // Verify only standalone profile remains
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "Home");

        // Verify profiles were deleted from storage
        let stored_profiles = app.storage.load_profiles(None).unwrap();
        assert_eq!(stored_profiles.len(), 1);
        assert_eq!(stored_profiles[0].name, "Home");

        // Verify Work/Special was removed, but OtherFolder remains
        assert_eq!(app.custom_folders, vec!["OtherFolder".to_string()]);
        assert_eq!(
            app.storage.load_folders().unwrap(),
            vec!["OtherFolder".to_string()]
        );

        // Verify expanded_folders was cleaned up
        assert!(!app.expanded_folders.contains("Work"));
        assert!(!app.expanded_folders.contains("Work/Europe"));

        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Deleted folder 'Work' and 2 profile(s)"))
        );
    }

    #[tokio::test]
    async fn test_sync_manager_online_empty_accounts() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        app.active_modal = ActiveModal::SyncManager(SyncManagerState::new());
        app.handle_key(KeyCode::Enter).await.unwrap();

        if let ActiveModal::SyncManager(state) = &app.active_modal {
            assert!(
                state
                    .error_message
                    .as_ref()
                    .unwrap()
                    .contains("No account selected")
            );
        } else {
            panic!("Expected SyncManager modal with error");
        }
    }

    #[tokio::test]
    async fn test_sync_manager_online_empty_credentials() {
        let mut storage = InMemoryStorage::new();
        let acc = Account::new("EmptyCreds");
        storage.save_account(&acc).unwrap();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        app.active_modal = ActiveModal::SyncManager(SyncManagerState::new());
        app.handle_key(KeyCode::Enter).await.unwrap();

        if let ActiveModal::SyncManager(state) = &app.active_modal {
            assert!(
                state
                    .error_message
                    .as_ref()
                    .unwrap()
                    .contains("empty username or password")
            );
        } else {
            panic!("Expected SyncManager modal with error");
        }
    }

    #[test]
    fn test_app_log_scrolling_and_auto_scroll() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        for i in 1..=20 {
            app.add_log(format!("Log line {}", i));
        }

        assert_eq!(app.logs.len(), 20);
        assert_eq!(app.logs_scroll_offset, 0);
        assert!(app.logs_auto_scroll);

        // Scroll up by 5 lines
        app.scroll_logs_up(5);
        assert_eq!(app.logs_scroll_offset, 5);
        assert!(!app.logs_auto_scroll);

        // While auto_scroll is false, adding a log preserves scroll offset
        app.add_log("New line while reading");
        assert_eq!(app.logs_scroll_offset, 5);
        assert!(!app.logs_auto_scroll);

        // Scroll to top
        app.scroll_logs_to_top();
        assert_eq!(app.logs_scroll_offset, app.logs.len() - 1);
        assert!(!app.logs_auto_scroll);

        // Scroll down
        app.scroll_logs_down(10);
        assert!(app.logs_scroll_offset < app.logs.len() - 1);

        // Scroll to bottom restores auto_scroll
        app.scroll_logs_to_bottom();
        assert_eq!(app.logs_scroll_offset, 0);
        assert!(app.logs_auto_scroll);
    }

    #[tokio::test]
    async fn test_app_key_scrolling_logs_and_pagedown() {
        let mut storage = InMemoryStorage::new();
        for i in 1..=25 {
            let p = Profile::new_openconnect(format!("Node {}", i), format!("10.0.0.{}:443", i));
            storage.save_profile(&p).unwrap();
        }
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        for i in 1..=50 {
            app.add_log(format!("Log {}", i));
        }

        // Test PageDown and PageUp on Profiles
        app.active_pane = ActivePane::Profiles;
        assert_eq!(app.selected_tree_idx, 0);

        app.handle_key(KeyCode::PageDown).await.unwrap();
        assert_eq!(app.selected_tree_idx, 10);

        app.handle_key(KeyCode::PageDown).await.unwrap();
        assert_eq!(app.selected_tree_idx, 20);

        app.handle_key(KeyCode::End).await.unwrap();
        assert_eq!(app.selected_tree_idx, 24);

        app.handle_key(KeyCode::Home).await.unwrap();
        assert_eq!(app.selected_tree_idx, 0);

        // Switch to Logs pane and test scroll keys
        app.active_pane = ActivePane::Logs;
        assert_eq!(app.logs_scroll_offset, 0);

        // 'k' scrolls up
        app.handle_key(KeyCode::Char('k')).await.unwrap();
        assert_eq!(app.logs_scroll_offset, 1);
        assert!(!app.logs_auto_scroll);

        // PageUp scrolls up by 10
        app.handle_key(KeyCode::PageUp).await.unwrap();
        assert_eq!(app.logs_scroll_offset, 11);

        // 'g' scrolls to top
        app.handle_key(KeyCode::Char('g')).await.unwrap();
        assert_eq!(app.logs_scroll_offset, 49);

        // 'G' scrolls to bottom and re-enables auto-scroll
        app.handle_key(KeyCode::Char('G')).await.unwrap();
        assert_eq!(app.logs_scroll_offset, 0);
        assert!(app.logs_auto_scroll);
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
