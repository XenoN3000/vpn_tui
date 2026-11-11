use crate::domain::account::{Account, AccountId};
use crate::domain::config::{
    Profile, ProfileId, ProtocolDefaults, ProxyCore, ProxyRoutingMode, SslPolicy, VpnProtocol,
};
use crate::domain::state::{AppEvent, CertWarningState, ConnectionState, LatencyState};
use crate::domain::subscription::{
    Subscription, current_timestamp_string, fetch_subscription_feed, parse_subscription_profiles,
};
use crate::infra::net_monitor::NetStats;
use crate::ports::pinger::Pinger;
use crate::ports::storage::{BioVpnPortalsConfig, ConfigStorage};
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

    // V2Ray fields
    pub v2_name: String,
    pub v2_link: String,
    pub v2_config_path: String,
    pub v2_routing_mode: ProxyRoutingMode,
    pub v2_core: ProxyCore,
    pub v2_custom_flags: String,
    pub v2_save_as_subscription: bool,

    pub inherit_defaults: bool,
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

            v2_name: String::new(),
            v2_link: String::new(),
            v2_config_path: String::new(),
            v2_routing_mode: ProxyRoutingMode::default(),
            v2_core: ProxyCore::default(),
            v2_custom_flags: String::new(),
            v2_save_as_subscription: true,

            inherit_defaults: true,
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
        state.inherit_defaults = profile.inherit_defaults;
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
            VpnProtocol::V2Ray => {
                state.v2_name = profile.name.clone();
                if let Some(endpoint) = &profile.proxy_endpoint {
                    if let Some(raw) = &endpoint.raw_link {
                        state.v2_link = raw.clone();
                    }
                }
                if let Some(path) = &profile.proxy_config_file {
                    state.v2_config_path = path.to_string_lossy().to_string();
                }
                state.v2_routing_mode = profile.proxy_routing_mode;
                state.v2_core = profile.proxy_core;
                state.v2_custom_flags = profile.flags.join(" ");
                state.v2_save_as_subscription = true;
            }
        }

        state
    }

    pub fn total_fields(&self) -> usize {
        match self.protocol {
            VpnProtocol::OpenConnect => 12,
            VpnProtocol::OpenVpn => 10,
            VpnProtocol::V2Ray => {
                if self.v2_link.starts_with("http://") || self.v2_link.starts_with("https://") {
                    9
                } else {
                    8
                }
            }
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
    pub target_account_idx: Option<usize>,
    pub with_cisco: bool,
    pub portal_urls: Vec<String>,
    pub selected_portal_idx: usize,
    pub status_message: Option<String>,
    pub error_message: Option<String>,
}

impl Default for SyncManagerState {
    fn default() -> Self {
        Self::with_portals(&BioVpnPortalsConfig::default())
    }
}

impl SyncManagerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_portals(config: &BioVpnPortalsConfig) -> Self {
        let urls = if config.urls.is_empty() {
            BioVpnPortalsConfig::default().urls
        } else {
            config.urls.clone()
        };
        let selected_idx = config
            .selected
            .as_ref()
            .and_then(|sel| urls.iter().position(|u| u == sel))
            .unwrap_or(0);

        Self {
            selected_method_idx: 0,
            target_account_idx: None,
            with_cisco: true,
            portal_urls: urls,
            selected_portal_idx: selected_idx,
            status_message: None,
            error_message: None,
        }
    }

    pub fn selected_portal_url(&self) -> String {
        self.portal_urls
            .get(self.selected_portal_idx)
            .cloned()
            .unwrap_or_else(|| "https://bio4co.com".to_string())
    }

    pub fn cycle_portal_next(&mut self) {
        if !self.portal_urls.is_empty() {
            self.selected_portal_idx = (self.selected_portal_idx + 1) % self.portal_urls.len();
        }
    }

    pub fn cycle_portal_prev(&mut self) {
        if !self.portal_urls.is_empty() {
            if self.selected_portal_idx == 0 {
                self.selected_portal_idx = self.portal_urls.len() - 1;
            } else {
                self.selected_portal_idx -= 1;
            }
        }
    }

    pub fn delete_current_portal(&mut self) {
        if !self.portal_urls.is_empty() {
            self.portal_urls.remove(self.selected_portal_idx);
            if self.portal_urls.is_empty() {
                let def = BioVpnPortalsConfig::default();
                self.portal_urls = def.urls;
                self.selected_portal_idx = 0;
            } else if self.selected_portal_idx >= self.portal_urls.len() {
                self.selected_portal_idx = self.portal_urls.len() - 1;
            }
        }
    }

    pub fn to_portals_config(&self) -> BioVpnPortalsConfig {
        BioVpnPortalsConfig {
            selected: Some(self.selected_portal_url()),
            urls: self.portal_urls.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionManagerState {
    pub subscriptions: Vec<Subscription>,
    pub selected_idx: usize,
    pub is_adding: bool,
    pub add_field_idx: usize,
    pub add_name: String,
    pub add_url: String,
    pub add_folder: String,
    pub add_routing_mode: ProxyRoutingMode,
    pub add_core_pref: ProxyCore,
    pub status_message: Option<String>,
    pub error_message: Option<String>,
}

impl Default for SubscriptionManagerState {
    fn default() -> Self {
        Self {
            subscriptions: Vec::new(),
            selected_idx: 0,
            is_adding: false,
            add_field_idx: 0,
            add_name: String::new(),
            add_url: String::new(),
            add_folder: "Subscription".to_string(),
            add_routing_mode: ProxyRoutingMode::default(),
            add_core_pref: ProxyCore::default(),
            status_message: None,
            error_message: None,
        }
    }
}

impl SubscriptionManagerState {
    pub fn new(subscriptions: Vec<Subscription>) -> Self {
        Self {
            subscriptions,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchInputState {
    pub text: String,
    pub target_account_idx: Option<usize>,
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
pub struct DefaultsModalState {
    pub oc_flags: String,
    pub ovpn_flags: String,
    pub field_idx: usize,
    pub error_msg: Option<String>,
}

impl DefaultsModalState {
    pub fn new(defaults: &ProtocolDefaults) -> Self {
        Self {
            oc_flags: defaults.openconnect_flags.join(" "),
            ovpn_flags: defaults.openvpn_flags.join(" "),
            field_idx: 0,
            error_msg: None,
        }
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
    Defaults(DefaultsModalState),
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
    AddBioVpnPortal {
        input: String,
        error: Option<String>,
        sync_state: SyncManagerState,
    },
    BatchInput(BatchInputState),
    SubscriptionManager(SubscriptionManagerState),
}

pub struct App<S: ConfigStorage, R: VpnRunner, P: Pinger> {
    pub storage: S,
    pub runner: R,
    pub pinger: P,

    pub accounts: Vec<Account>,
    pub selected_account_idx: usize,

    pub profiles: Vec<Profile>,
    pub selected_profile_idx: usize,

    pub subscriptions: Vec<Subscription>,
    pub biovpn_portals: BioVpnPortalsConfig,
    pub defaults: ProtocolDefaults,

    pub active_pane: ActivePane,
    pub active_modal: ActiveModal,

    pub connection_state: ConnectionState,
    pub active_profile_name: Option<String>,
    pub net_stats: Option<NetStats>,
    pub logs: Vec<String>,

    pub event_tx: Option<mpsc::UnboundedSender<LogEvent>>,
    pub event_rx: Option<mpsc::UnboundedReceiver<LogEvent>>,
    pub app_event_tx: mpsc::UnboundedSender<AppEvent>,
    pub app_event_rx: mpsc::UnboundedReceiver<AppEvent>,
    pub should_quit: bool,
    pub is_syncing: bool,
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
        let subscriptions = storage.load_subscriptions().unwrap_or_default();
        let biovpn_portals = storage.load_biovpn_portals().unwrap_or_default();
        let defaults = storage.load_defaults().unwrap_or_default();

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

        let (app_event_tx, app_event_rx) = mpsc::unbounded_channel();

        Self {
            storage,
            runner,
            pinger,
            accounts,
            selected_account_idx: 0,
            profiles,
            selected_profile_idx: 0,
            subscriptions,
            biovpn_portals,
            defaults,
            active_pane: ActivePane::Profiles,
            active_modal: ActiveModal::None,
            connection_state: ConnectionState::Disconnected,
            active_profile_name: None,
            net_stats: None,
            logs: Vec::new(),
            event_tx: None,
            event_rx: None,
            app_event_tx,
            app_event_rx,
            should_quit: false,
            is_syncing: false,
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

        let mut app_events = Vec::new();
        while let Ok(app_event) = self.app_event_rx.try_recv() {
            app_events.push(app_event);
        }
        for app_event in app_events {
            self.handle_app_event(app_event);
        }
    }

    pub async fn wait_for_sync(&mut self) {
        while self.is_syncing {
            if let Some(ev) = self.app_event_rx.recv().await {
                self.handle_app_event(ev);
            } else {
                break;
            }
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
        self.subscriptions = self.storage.load_subscriptions().unwrap_or_default();
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

    pub async fn sync_subscription_by_idx(&mut self, idx: usize) -> Result<usize> {
        if idx >= self.subscriptions.len() {
            anyhow::bail!("Invalid subscription index: {}", idx);
        }
        let sub = self.subscriptions[idx].clone();
        let body = fetch_subscription_feed(&sub.url).await?;
        let profiles =
            parse_subscription_profiles(&body, &sub.folder, sub.routing_mode, sub.core_pref);
        if profiles.is_empty() {
            anyhow::bail!("No valid proxy nodes found in subscription feed");
        }

        // Prune existing profiles in this folder
        let existing = self
            .storage
            .load_profiles(Some(VpnProtocol::V2Ray))
            .unwrap_or_default();
        for p in existing {
            if p.group.as_deref() == Some(&sub.folder) {
                let _ = self.storage.delete_profile(&p.id);
            }
        }

        // Save new profiles
        for prof in &profiles {
            self.storage.save_profile(prof)?;
        }

        // Update timestamp
        self.subscriptions[idx].last_synced = Some(current_timestamp_string());
        let _ = self.storage.save_subscriptions(&self.subscriptions);

        self.ensure_custom_folder(&sub.folder);
        self.expanded_folders.insert(sub.folder.clone());
        self.reload_profiles();
        self.add_log(format!(
            "Synced subscription '{}': updated {} nodes in '{}'.",
            sub.name,
            profiles.len(),
            sub.folder
        ));
        Ok(profiles.len())
    }

    pub async fn sync_all_subscriptions(&mut self) -> Result<(usize, usize)> {
        let mut total_nodes = 0;
        let mut successful = 0;
        let count = self.subscriptions.len();
        for idx in 0..count {
            if let Ok(nodes) = self.sync_subscription_by_idx(idx).await {
                total_nodes += nodes;
                successful += 1;
            }
        }
        Ok((successful, total_nodes))
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

    pub fn selected_profile_idx(&self) -> Option<usize> {
        let tree = self.visible_tree();
        if let Some(crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. }) =
            tree.get(self.selected_tree_idx)
        {
            return Some(*profile_idx);
        }
        if self.selected_profile_idx < self.profiles.len() {
            Some(self.selected_profile_idx)
        } else {
            None
        }
    }

    pub fn toggle_selected_profile_inheritance(&mut self) -> Result<()> {
        if let Some(idx) = self.selected_profile_idx() {
            if let Some(prof) = self.profiles.get_mut(idx) {
                if prof.protocol == VpnProtocol::OpenConnect || prof.protocol == VpnProtocol::OpenVpn {
                    prof.inherit_defaults = !prof.inherit_defaults;
                    let updated = prof.clone();
                    self.storage.save_profile(&updated)?;
                    let status = if updated.inherit_defaults {
                        "[x] ON"
                    } else {
                        "[ ] OFF"
                    };
                    self.add_log(format!(
                        "Profile '{}': default flags inheritance toggled to {}",
                        updated.name, status
                    ));
                }
            }
        }
        Ok(())
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

    pub fn ping_selected(&mut self) {
        let tree = self.visible_tree();
        let profile = if !tree.is_empty() {
            match tree.get(self.selected_tree_idx) {
                Some(crate::ui::tree::VisibleTreeNode::Profile { profile_idx, .. }) => {
                    self.profiles.get(*profile_idx)
                }
                _ => None,
            }
        } else {
            self.profiles.get(self.selected_profile_idx)
        };

        let (id, endpoint) = match profile {
            Some(p) => (p.id.clone(), p.endpoint.clone()),
            None => return,
        };

        if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
            p.latency = LatencyState::Pinging;
        }

        let pinger = self.pinger.clone();
        let tx = self.app_event_tx.clone();
        tokio::spawn(async move {
            let latency = pinger.ping(&endpoint, Duration::from_secs(2)).await;
            let _ = tx.send(AppEvent::PingResult {
                profile_id: id,
                latency,
            });
        });
    }

    pub fn ping_all(&mut self) {
        for profile in &mut self.profiles {
            profile.latency = LatencyState::Pinging;
        }

        for profile in &self.profiles {
            let id = profile.id.clone();
            let endpoint = profile.endpoint.clone();
            let pinger = self.pinger.clone();
            let tx = self.app_event_tx.clone();
            tokio::spawn(async move {
                let latency = pinger.ping(&endpoint, Duration::from_secs(2)).await;
                let _ = tx.send(AppEvent::PingResult {
                    profile_id: id,
                    latency,
                });
            });
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

        let needs_sudo = match profile.protocol {
            VpnProtocol::OpenConnect | VpnProtocol::OpenVpn => true,
            VpnProtocol::V2Ray => profile.proxy_routing_mode == ProxyRoutingMode::Tun,
        };

        if needs_sudo && !self.runner.check_sudo_cached().await {
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

    pub fn handle_app_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::VpnLog(log) => self.handle_log_event(log),
            AppEvent::PingResult {
                profile_id,
                latency,
            } => {
                if let Some(p) = self.profiles.iter_mut().find(|p| p.id == profile_id) {
                    p.latency = latency;
                }
            }
            AppEvent::SyncProgress(msg) => {
                self.add_log(msg);
            }
            AppEvent::BioVpnSyncCompleted {
                profiles,
                folders,
                summary_log,
            } => {
                self.is_syncing = false;
                for prof in &profiles {
                    let _ = self.storage.save_profile(prof);
                }
                for folder in folders {
                    self.ensure_custom_folder(&folder);
                    let mut path_accum = String::new();
                    for part in folder.split('/') {
                        if !path_accum.is_empty() {
                            path_accum.push('/');
                        }
                        path_accum.push_str(part);
                        self.expanded_folders.insert(path_accum.clone());
                    }
                }
                self.reload_profiles();
                self.expanded_folders.insert("BioVPN".to_string());
                self.expanded_folders.insert("BioVPN/Cisco".to_string());
                self.expanded_folders.insert("BioVPN/OpenVPN".to_string());
                self.add_log(summary_log);
            }
            AppEvent::BioVpnSyncFailed(err) => {
                self.is_syncing = false;
                self.add_log(format!("[ERR] BioVPN sync failed: {}", err));
            }
        }
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
                    if adder.protocol == VpnProtocol::OpenVpn
                        || adder.protocol == VpnProtocol::V2Ray
                    {
                        let initial = if adder.protocol == VpnProtocol::OpenVpn
                            && !adder.ovpn_path.trim().is_empty()
                        {
                            Some(std::path::PathBuf::from(adder.ovpn_path.trim()))
                        } else if adder.protocol == VpnProtocol::V2Ray
                            && !adder.v2_config_path.trim().is_empty()
                        {
                            Some(std::path::PathBuf::from(adder.v2_config_path.trim()))
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
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            9 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            2 => adder.oc_name.push(' '),
                            3 => adder.oc_endpoint.push(' '),
                            5 => adder.oc_authgroup.push(' '),
                            6 => adder.oc_servercert.push(' '),
                            10 => adder.oc_custom_flags.push(' '),
                            11 => {
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
                                adder.protocol = VpnProtocol::V2Ray;
                                adder.field_idx = 0;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            6 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            7 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            2 => adder.ovpn_name.push(' '),
                            3 => adder.ovpn_path.push(' '),
                            4 => adder.ovpn_remote.push(' '),
                            8 => adder.ovpn_custom_flags.push(' '),
                            9 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.push(' ');
                                    adder.group.push(' ');
                                } else {
                                    adder.next_folder_option();
                                }
                            }
                            _ => {}
                        },
                        VpnProtocol::V2Ray => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenConnect;
                                adder.field_idx = 0;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            2 => adder.v2_name.push(' '),
                            3 => adder.v2_link.push(' '),
                            4 => adder.v2_config_path.push(' '),
                            5 => {
                                adder.v2_routing_mode = adder.v2_routing_mode.next();
                            }
                            6 => {
                                adder.v2_core = adder.v2_core.next();
                            }
                            7 => {
                                if adder.is_on_new_folder() {
                                    adder.custom_group_input.push(' ');
                                    adder.group.push(' ');
                                } else {
                                    adder.next_folder_option();
                                }
                            }
                            8 => {
                                adder.v2_save_as_subscription = !adder.v2_save_as_subscription;
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
                                adder.protocol = VpnProtocol::V2Ray;
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
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            9 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            11 => {
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
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            6 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            7 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            9 => {
                                adder.prev_folder_option();
                            }
                            _ => {}
                        },
                        VpnProtocol::V2Ray => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenVpn;
                            }
                            1 => {
                                adder.account_idx =
                                    prev_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.v2_routing_mode = adder.v2_routing_mode.next();
                            }
                            6 => {
                                adder.v2_core = adder.v2_core.next();
                            }
                            7 => {
                                adder.prev_folder_option();
                            }
                            8 => {
                                adder.v2_save_as_subscription = !adder.v2_save_as_subscription;
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
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            9 => {
                                adder.oc_no_dtls = !adder.oc_no_dtls;
                            }
                            11 => {
                                adder.next_folder_option();
                            }
                            _ => {}
                        },
                        VpnProtocol::OpenVpn => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::V2Ray;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.inherit_defaults = !adder.inherit_defaults;
                            }
                            6 => {
                                adder.ovpn_redirect_gateway = !adder.ovpn_redirect_gateway;
                            }
                            7 => {
                                adder.ovpn_dev_tun = !adder.ovpn_dev_tun;
                            }
                            9 => {
                                adder.next_folder_option();
                            }
                            _ => {}
                        },
                        VpnProtocol::V2Ray => match adder.field_idx {
                            0 => {
                                adder.protocol = VpnProtocol::OpenConnect;
                            }
                            1 => {
                                adder.account_idx =
                                    next_account_idx(adder.account_idx, self.accounts.len());
                            }
                            5 => {
                                adder.v2_routing_mode = adder.v2_routing_mode.next();
                            }
                            6 => {
                                adder.v2_core = adder.v2_core.next();
                            }
                            7 => {
                                adder.next_folder_option();
                            }
                            8 => {
                                adder.v2_save_as_subscription = !adder.v2_save_as_subscription;
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
                            10 => {
                                adder.oc_custom_flags.pop();
                            }
                            11 => {
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
                            8 => {
                                adder.ovpn_custom_flags.pop();
                            }
                            9 => {
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
                        VpnProtocol::V2Ray => match adder.field_idx {
                            2 => {
                                adder.v2_name.pop();
                            }
                            3 => {
                                adder.v2_link.pop();
                            }
                            4 => {
                                adder.v2_config_path.pop();
                            }
                            7 => {
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
                            10 => adder.oc_custom_flags.push(c),
                            11 => {
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
                            8 => adder.ovpn_custom_flags.push(c),
                            9 => {
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
                        VpnProtocol::V2Ray => match adder.field_idx {
                            2 => adder.v2_name.push(c),
                            3 => adder.v2_link.push(c),
                            4 => adder.v2_config_path.push(c),
                            7 => {
                                if !adder.is_on_new_folder() {
                                    adder.folder_option_idx =
                                        adder.folder_options.len().saturating_sub(1);
                                    adder.custom_group_input.clear();
                                    adder.group.clear();
                                }
                                adder.custom_group_input.push(c);
                                adder.group.push(c);
                            }
                            8 => {
                                if c == ' ' {
                                    adder.v2_save_as_subscription = !adder.v2_save_as_subscription;
                                }
                            }
                            _ => {}
                        },
                    }
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                }
                KeyCode::Enter => {
                    self.submit_config_adder(adder).await?;
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
            ActiveModal::Defaults(mut state) => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::None;
                }
                KeyCode::Tab | KeyCode::Down => {
                    state.field_idx = (state.field_idx + 1) % 2;
                    self.active_modal = ActiveModal::Defaults(state);
                }
                KeyCode::BackTab | KeyCode::Up => {
                    state.field_idx = if state.field_idx == 0 { 1 } else { 0 };
                    self.active_modal = ActiveModal::Defaults(state);
                }
                KeyCode::Char(c) => {
                    match state.field_idx {
                        0 => state.oc_flags.push(c),
                        1 => state.ovpn_flags.push(c),
                        _ => {}
                    }
                    state.error_msg = None;
                    self.active_modal = ActiveModal::Defaults(state);
                }
                KeyCode::Backspace => {
                    match state.field_idx {
                        0 => {
                            state.oc_flags.pop();
                        }
                        1 => {
                            state.ovpn_flags.pop();
                        }
                        _ => {}
                    }
                    state.error_msg = None;
                    self.active_modal = ActiveModal::Defaults(state);
                }
                KeyCode::Enter => {
                    let oc_flags: Vec<String> = state
                        .oc_flags
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    let ovpn_flags: Vec<String> = state
                        .ovpn_flags
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();

                    let new_defaults = ProtocolDefaults {
                        openconnect_flags: oc_flags,
                        openvpn_flags: ovpn_flags,
                    };

                    if let Err(e) = self.storage.save_defaults(&new_defaults) {
                        state.error_msg = Some(format!("Failed to save defaults: {}", e));
                        self.active_modal = ActiveModal::Defaults(state);
                    } else {
                        self.defaults = new_defaults.clone();
                        self.runner.set_defaults(new_defaults);
                        self.add_log("Protocol default flags updated and saved.");
                        self.active_modal = ActiveModal::None;
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::Defaults(state);
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
                KeyCode::Left | KeyCode::Char('h') if state.selected_method_idx == 0 => {
                    state.cycle_portal_prev();
                    self.biovpn_portals = state.to_portals_config();
                    let _ = self.storage.save_biovpn_portals(&self.biovpn_portals);
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Right | KeyCode::Char('l') if state.selected_method_idx == 0 => {
                    state.cycle_portal_next();
                    self.biovpn_portals = state.to_portals_config();
                    let _ = self.storage.save_biovpn_portals(&self.biovpn_portals);
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Char('a') if state.selected_method_idx == 0 => {
                    self.active_modal = ActiveModal::AddBioVpnPortal {
                        input: String::new(),
                        error: None,
                        sync_state: state,
                    };
                }
                KeyCode::Char('d') if state.selected_method_idx == 0 => {
                    state.delete_current_portal();
                    self.biovpn_portals = state.to_portals_config();
                    let _ = self.storage.save_biovpn_portals(&self.biovpn_portals);
                    state.status_message = Some(format!(
                        "Portal mirror updated (active: {})",
                        state.selected_portal_url()
                    ));
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    state.selected_method_idx = state.selected_method_idx.saturating_sub(1);
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if state.selected_method_idx < 3 {
                        state.selected_method_idx += 1;
                    }
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Tab => {
                    state.target_account_idx =
                        next_account_idx(state.target_account_idx, self.accounts.len());
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::BackTab => {
                    state.target_account_idx =
                        prev_account_idx(state.target_account_idx, self.accounts.len());
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Char(' ') => {
                    state.with_cisco = !state.with_cisco;
                    self.active_modal = ActiveModal::SyncManager(state);
                }
                KeyCode::Enter => match state.selected_method_idx {
                    0 => {
                        if self.is_syncing {
                            self.add_log("[WARN] BioVPN sync is already running in background.");
                            self.active_modal = ActiveModal::None;
                            return Ok(());
                        }

                        let (target_acc_id, creds) = match state.target_account_idx {
                            Some(idx) => match self.accounts.get(idx) {
                                Some(acc) => {
                                    let creds = acc.credentials.as_ref();
                                    let u =
                                        creds.and_then(|c| c.username.clone()).unwrap_or_default();
                                    let p =
                                        creds.and_then(|c| c.password.clone()).unwrap_or_default();
                                    if u.trim().is_empty() || p.trim().is_empty() {
                                        state.error_message = Some(format!(
                                            "Account '{}' has empty username or password.",
                                            acc.id.0
                                        ));
                                        self.active_modal = ActiveModal::SyncManager(state);
                                        return Ok(());
                                    }
                                    (Some(acc.id.clone()), Some((u, p)))
                                }
                                None => {
                                    state.error_message =
                                        Some("No account selected for sync.".to_string());
                                    self.active_modal = ActiveModal::SyncManager(state);
                                    return Ok(());
                                }
                            },
                            None => (None, None),
                        };

                        let portal_url = state.selected_portal_url();
                        let client = match crate::infra::biovpn_client::ReqwestBioVpnClient::new(
                            Some(&portal_url),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                state.error_message = Some(format!("HTTP client error: {}", e));
                                self.active_modal = ActiveModal::SyncManager(state);
                                return Ok(());
                            }
                        };

                        let dest = {
                            let root = self.storage.get_config_root();
                            if root.starts_with("/mock") {
                                std::env::temp_dir().join("vpn_tui_test_openvpn")
                            } else {
                                root.join("openvpn")
                            }
                        };

                        let tx = self.app_event_tx.clone();
                        let with_cisco = state.with_cisco;

                        self.active_modal = ActiveModal::None;
                        self.is_syncing = true;
                        self.add_log(format!(
                            "[SYNC] Starting BioVPN sync from {}...",
                            portal_url
                        ));

                        tokio::spawn(async move {
                            let tx_logger = tx.clone();
                            let client = client.with_logger(move |msg| {
                                let _ = tx_logger.send(AppEvent::SyncProgress(msg));
                            });

                            use crate::ports::biovpn::BioVpnClient;
                            let bundle_res = match creds {
                                Some((username, password)) => {
                                    client.fetch_bundle(&username, &password).await
                                }
                                None => client.fetch_direct_bundle().await,
                            };

                            let sync_data = match bundle_res {
                                Ok(data) => data,
                                Err(e) => {
                                    let _ = tx.send(AppEvent::BioVpnSyncFailed(e.to_string()));
                                    return;
                                }
                            };

                            for log_msg in sync_data.logs {
                                let _ = tx.send(AppEvent::SyncProgress(log_msg));
                            }

                            let _ = std::fs::create_dir_all(&dest);

                            let mut all_profiles = Vec::new();
                            let mut all_folders = Vec::new();
                            let mut html_cisco_count = 0;
                            let mut imported_groups = Vec::new();

                            if with_cisco {
                                if let Some(ref html) = sync_data.dashboard_html {
                                    if let Ok(parsed_html) =
                                        crate::domain::importer::ProfileImporter::parse_portal_html(
                                            html,
                                            target_acc_id.clone(),
                                            Some(&portal_url),
                                        )
                                    {
                                        for prof in parsed_html.profiles {
                                            if let Some(ref grp) = prof.group {
                                                all_folders.push(grp.clone());
                                            }
                                            all_profiles.push(prof);
                                        }
                                        html_cisco_count = all_profiles.len();
                                        imported_groups = parsed_html.groups;
                                    }
                                }
                            }

                            let mut table_ovpn_count = 0;
                            for item in sync_data.individual_ovpns {
                                let target_file_path = dest.join(&item.filename);
                                if let Err(e) = std::fs::write(&target_file_path, &item.content) {
                                    let _ = tx.send(AppEvent::SyncProgress(format!(
                                        "[WARN] Failed to save OpenVPN config {}: {}",
                                        item.filename, e
                                    )));
                                    continue;
                                }

                                let ov_profile =
                                    crate::domain::importer::ProfileImporter::create_table_openvpn_profile(
                                        &item.server_name,
                                        &item.country_group,
                                        &item.content,
                                        &target_file_path,
                                        target_acc_id.clone(),
                                    );

                                if let Some(ref grp) = ov_profile.group {
                                    all_folders.push(grp.clone());
                                }
                                all_profiles.push(ov_profile);
                                table_ovpn_count += 1;
                            }

                            let cursor = std::io::Cursor::new(sync_data.zip_bytes);
                            match crate::domain::importer::ProfileImporter::import_zip(
                                cursor,
                                &dest,
                                target_acc_id,
                                with_cisco,
                            ) {
                                Ok(summary) => {
                                    if summary.openvpn_count > 0 || table_ovpn_count > 0 {
                                        all_folders.push("BioVPN/OpenVPN".to_string());
                                    }
                                    if summary.openconnect_count > 0 || html_cisco_count > 0 {
                                        all_folders.push("BioVPN/Cisco".to_string());
                                    }
                                    all_folders.push("BioVPN".to_string());

                                    all_profiles.extend(summary.profiles);

                                    let total_cisco = html_cisco_count + summary.openconnect_count;
                                    let total_openvpn = summary.openvpn_count + table_ovpn_count;

                                    let summary_log = if !imported_groups.is_empty() {
                                        format!(
                                            "BioVPN sync completed: imported {} OpenVPN and {} Cisco profiles across {} groups.",
                                            total_openvpn,
                                            total_cisco,
                                            imported_groups.len()
                                        )
                                    } else {
                                        format!(
                                            "BioVPN sync completed: imported {} OpenVPN and {} Cisco profiles.",
                                            total_openvpn, total_cisco
                                        )
                                    };

                                    let _ = tx.send(AppEvent::BioVpnSyncCompleted {
                                        profiles: all_profiles,
                                        folders: all_folders,
                                        summary_log,
                                    });
                                }
                                Err(e) => {
                                    let _ = tx.send(AppEvent::BioVpnSyncFailed(format!(
                                        "Bundle extraction error: {}",
                                        e
                                    )));
                                }
                            }
                        });
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
                    3 => {
                        self.active_modal = ActiveModal::SubscriptionManager(
                            SubscriptionManagerState::new(self.subscriptions.clone()),
                        );
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
                        let is_html = selected_file
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(|s| {
                                s.eq_ignore_ascii_case("html") || s.eq_ignore_ascii_case("htm")
                            })
                            .unwrap_or(false);
                        if is_zip {
                            let target_acc = sync_state
                                .target_account_idx
                                .and_then(|idx| self.accounts.get(idx))
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
                        } else if is_html {
                            match std::fs::read_to_string(&selected_file) {
                                Ok(html_content) => {
                                    let target_acc = sync_state
                                        .target_account_idx
                                        .and_then(|idx| self.accounts.get(idx))
                                        .map(|a| a.id.clone());
                                    match crate::domain::importer::ProfileImporter::parse_portal_html(
                                        &html_content,
                                        target_acc,
                                        None,
                                    ) {
                                        Ok(parsed) if !parsed.profiles.is_empty() => {
                                            let count = parsed.profiles.len();
                                            for prof in &parsed.profiles {
                                                let _ = self.storage.save_profile(prof);
                                                if let Some(ref grp) = prof.group {
                                                    self.ensure_custom_folder(grp);
                                                    let mut path_accum = String::new();
                                                    for part in grp.split('/') {
                                                        if !path_accum.is_empty() {
                                                            path_accum.push('/');
                                                        }
                                                        path_accum.push_str(part);
                                                        self.expanded_folders.insert(path_accum.clone());
                                                    }
                                                }
                                            }
                                            self.reload_profiles();
                                            self.expanded_folders.insert("BioVPN".to_string());
                                            self.expanded_folders.insert("BioVPN/Cisco".to_string());
                                            self.add_log(format!(
                                                "Imported {} Cisco profiles across {} groups from HTML.",
                                                count, parsed.groups.len()
                                            ));
                                            self.active_modal = ActiveModal::None;
                                        }
                                        Ok(_) => {
                                            let mut sync = sync_state;
                                            sync.error_message = Some(
                                                "No valid server profiles found in HTML file."
                                                    .into(),
                                            );
                                            self.active_modal = ActiveModal::SyncManager(sync);
                                        }
                                        Err(e) => {
                                            let mut sync = sync_state;
                                            sync.error_message =
                                                Some(format!("HTML parse error: {}", e));
                                            self.active_modal = ActiveModal::SyncManager(sync);
                                        }
                                    }
                                }
                                Err(e) => {
                                    let mut sync = sync_state;
                                    sync.error_message =
                                        Some(format!("Could not read HTML file: {}", e));
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
            ActiveModal::AddBioVpnPortal {
                mut input,
                error,
                mut sync_state,
            } => match code {
                KeyCode::Esc => {
                    self.active_modal = ActiveModal::SyncManager(sync_state);
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.active_modal = ActiveModal::AddBioVpnPortal {
                        input,
                        error: None,
                        sync_state,
                    };
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    self.active_modal = ActiveModal::AddBioVpnPortal {
                        input,
                        error: None,
                        sync_state,
                    };
                }
                KeyCode::Enter => {
                    if let Some(norm) = BioVpnPortalsConfig::normalize_url(&input) {
                        if !sync_state.portal_urls.contains(&norm) {
                            sync_state.portal_urls.push(norm.clone());
                        }
                        sync_state.selected_portal_idx = sync_state
                            .portal_urls
                            .iter()
                            .position(|u| u == &norm)
                            .unwrap_or(0);
                        self.biovpn_portals = sync_state.to_portals_config();
                        let _ = self.storage.save_biovpn_portals(&self.biovpn_portals);
                        sync_state.status_message = Some(format!("Added portal mirror: {}", norm));
                        sync_state.error_message = None;
                        self.active_modal = ActiveModal::SyncManager(sync_state);
                    } else {
                        self.active_modal = ActiveModal::AddBioVpnPortal {
                            input,
                            error: Some(
                                "Please enter a valid URL or domain (e.g. n1buy.info)".to_string(),
                            ),
                            sync_state,
                        };
                    }
                }
                _ => {
                    self.active_modal = ActiveModal::AddBioVpnPortal {
                        input,
                        error,
                        sync_state,
                    };
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
                    let target_acc = state
                        .target_account_idx
                        .and_then(|idx| self.accounts.get(idx))
                        .map(|a| a.id.clone());
                    match crate::domain::importer::ProfileImporter::parse_server_list(
                        &state.text,
                        target_acc,
                    ) {
                        Ok(profiles) if !profiles.is_empty() => {
                            let count = profiles.len();
                            for prof in &profiles {
                                let _ = self.storage.save_profile(prof);
                                if let Some(ref grp) = prof.group {
                                    self.ensure_custom_folder(grp);
                                    let mut path_accum = String::new();
                                    for part in grp.split('/') {
                                        if !path_accum.is_empty() {
                                            path_accum.push('/');
                                        }
                                        path_accum.push_str(part);
                                        self.expanded_folders.insert(path_accum.clone());
                                    }
                                }
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
            ActiveModal::SubscriptionManager(mut state) => match code {
                KeyCode::Esc => {
                    if state.is_adding {
                        state.is_adding = false;
                        self.active_modal = ActiveModal::SubscriptionManager(state);
                    } else {
                        self.active_modal = ActiveModal::SyncManager(SyncManagerState {
                            selected_method_idx: 3,
                            ..Default::default()
                        });
                    }
                }
                KeyCode::Up | KeyCode::Char('k') if !state.is_adding => {
                    state.selected_idx = state.selected_idx.saturating_sub(1);
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Down | KeyCode::Char('j') if !state.is_adding => {
                    if state.selected_idx + 1 < self.subscriptions.len() {
                        state.selected_idx += 1;
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char('u') if !state.is_adding => {
                    if !self.subscriptions.is_empty()
                        && state.selected_idx < self.subscriptions.len()
                    {
                        match self.sync_subscription_by_idx(state.selected_idx).await {
                            Ok(count) => {
                                state.subscriptions = self.subscriptions.clone();
                                state.status_message =
                                    Some(format!("Synced {} nodes successfully", count));
                                state.error_message = None;
                            }
                            Err(e) => {
                                state.error_message = Some(format!("Sync failed: {}", e));
                                state.status_message = None;
                            }
                        }
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char('U') if !state.is_adding => {
                    if !self.subscriptions.is_empty() {
                        match self.sync_all_subscriptions().await {
                            Ok((subs, nodes)) => {
                                state.subscriptions = self.subscriptions.clone();
                                state.status_message = Some(format!(
                                    "Updated {} subscriptions ({} nodes total)",
                                    subs, nodes
                                ));
                                state.error_message = None;
                            }
                            Err(e) => {
                                state.error_message = Some(format!("Sync failed: {}", e));
                                state.status_message = None;
                            }
                        }
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char('a') if !state.is_adding => {
                    state.is_adding = true;
                    state.add_field_idx = 0;
                    state.add_name.clear();
                    state.add_url.clear();
                    state.add_folder = "Subscription".to_string();
                    state.status_message = None;
                    state.error_message = None;
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char('d') if !state.is_adding => {
                    if !self.subscriptions.is_empty()
                        && state.selected_idx < self.subscriptions.len()
                    {
                        let removed = self.subscriptions.remove(state.selected_idx);
                        let _ = self.storage.save_subscriptions(&self.subscriptions);
                        state.subscriptions = self.subscriptions.clone();
                        if state.selected_idx >= self.subscriptions.len()
                            && !self.subscriptions.is_empty()
                        {
                            state.selected_idx = self.subscriptions.len() - 1;
                        }
                        state.status_message =
                            Some(format!("Deleted subscription '{}'", removed.name));
                        state.error_message = None;
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Tab | KeyCode::Down if state.is_adding => {
                    state.add_field_idx = (state.add_field_idx + 1) % 5;
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::BackTab | KeyCode::Up if state.is_adding => {
                    state.add_field_idx = if state.add_field_idx == 0 {
                        4
                    } else {
                        state.add_field_idx - 1
                    };
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Backspace if state.is_adding => {
                    match state.add_field_idx {
                        0 => {
                            state.add_name.pop();
                        }
                        1 => {
                            state.add_url.pop();
                        }
                        2 => {
                            state.add_folder.pop();
                        }
                        _ => {}
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char(' ') if state.is_adding => {
                    match state.add_field_idx {
                        0 => state.add_name.push(' '),
                        1 => state.add_url.push(' '),
                        2 => state.add_folder.push(' '),
                        3 => state.add_routing_mode = state.add_routing_mode.next(),
                        4 => state.add_core_pref = state.add_core_pref.next(),
                        _ => {}
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Char(c) if state.is_adding => {
                    match state.add_field_idx {
                        0 => state.add_name.push(c),
                        1 => state.add_url.push(c),
                        2 => state.add_folder.push(c),
                        3 => state.add_routing_mode = state.add_routing_mode.next(),
                        4 => state.add_core_pref = state.add_core_pref.next(),
                        _ => {}
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                KeyCode::Enter if state.is_adding => {
                    let url = state.add_url.trim().to_string();
                    let name = if state.add_name.trim().is_empty() {
                        "Subscription".to_string()
                    } else {
                        state.add_name.trim().to_string()
                    };
                    let folder = if state.add_folder.trim().is_empty() {
                        name.clone()
                    } else {
                        state.add_folder.trim().to_string()
                    };

                    if url.is_empty()
                        || (!url.starts_with("http://") && !url.starts_with("https://"))
                    {
                        state.error_message =
                            Some("Please enter a valid HTTP/HTTPS URL".to_string());
                        self.active_modal = ActiveModal::SubscriptionManager(state);
                        return Ok(());
                    }

                    match fetch_subscription_feed(&url).await {
                        Ok(body) => {
                            let profiles = parse_subscription_profiles(
                                &body,
                                &folder,
                                state.add_routing_mode,
                                state.add_core_pref,
                            );
                            if profiles.is_empty() {
                                state.error_message = Some(
                                    "No valid proxy nodes found in subscription feed".to_string(),
                                );
                                self.active_modal = ActiveModal::SubscriptionManager(state);
                                return Ok(());
                            }

                            let mut sub = Subscription::new(&name, &url, &folder)
                                .with_routing_mode(state.add_routing_mode)
                                .with_core_pref(state.add_core_pref);
                            sub.last_synced = Some(current_timestamp_string());

                            for prof in &profiles {
                                let _ = self.storage.save_profile(prof);
                            }
                            self.ensure_custom_folder(&folder);
                            self.expanded_folders.insert(folder.clone());

                            if let Some(pos) = self
                                .subscriptions
                                .iter()
                                .position(|s| s.url == url || s.id == sub.id)
                            {
                                self.subscriptions[pos] = sub;
                            } else {
                                self.subscriptions.push(sub);
                            }
                            let _ = self.storage.save_subscriptions(&self.subscriptions);

                            self.reload_profiles();
                            state.subscriptions = self.subscriptions.clone();
                            state.is_adding = false;
                            state.status_message =
                                Some(format!("Added '{}' with {} nodes", name, profiles.len()));
                            state.error_message = None;
                            self.active_modal = ActiveModal::SubscriptionManager(state);
                        }
                        Err(e) => {
                            state.error_message = Some(format!("Failed to fetch feed: {}", e));
                            self.active_modal = ActiveModal::SubscriptionManager(state);
                        }
                    }
                }
                KeyCode::Enter if !state.is_adding => {
                    if !self.subscriptions.is_empty()
                        && state.selected_idx < self.subscriptions.len()
                    {
                        match self.sync_subscription_by_idx(state.selected_idx).await {
                            Ok(count) => {
                                state.subscriptions = self.subscriptions.clone();
                                state.status_message =
                                    Some(format!("Synced {} nodes successfully", count));
                                state.error_message = None;
                            }
                            Err(e) => {
                                state.error_message = Some(format!("Sync failed: {}", e));
                                state.status_message = None;
                            }
                        }
                    }
                    self.active_modal = ActiveModal::SubscriptionManager(state);
                }
                _ => {
                    self.active_modal = ActiveModal::SubscriptionManager(state);
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
                    ActivePane::Flags => {
                        self.toggle_selected_profile_inheritance()?;
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
                    ActivePane::Flags => {
                        self.toggle_selected_profile_inheritance()?;
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
                    self.ping_selected();
                }
                KeyCode::Char('P') => {
                    self.ping_all();
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
                    let mut sync_state = SyncManagerState::with_portals(&self.biovpn_portals);
                    if !self.accounts.is_empty() {
                        sync_state.target_account_idx =
                            Some(self.selected_account_idx.min(self.accounts.len() - 1));
                    }
                    self.active_modal = ActiveModal::SyncManager(sync_state);
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
                KeyCode::Char('D') => {
                    if matches!(self.active_pane, ActivePane::Profiles | ActivePane::Flags) {
                        self.active_modal =
                            ActiveModal::Defaults(DefaultsModalState::new(&self.defaults));
                    }
                }
                KeyCode::Char('i') | KeyCode::Char('I') => {
                    if matches!(self.active_pane, ActivePane::Profiles | ActivePane::Flags) {
                        self.toggle_selected_profile_inheritance()?;
                    }
                }
                _ => {}
            },
        }

        Ok(())
    }

    pub async fn submit_config_adder(&mut self, mut adder: ConfigAdderState) -> Result<()> {
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
                prof.inherit_defaults = adder.inherit_defaults;
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
                            prof.inherit_defaults = adder.inherit_defaults;
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
                    prof.inherit_defaults = adder.inherit_defaults;
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
            VpnProtocol::V2Ray => {
                let name = adder.v2_name.trim();
                let link = adder.v2_link.trim();
                let config_path = adder.v2_config_path.trim();

                if name.is_empty() && link.is_empty() && config_path.is_empty() {
                    adder.error_msg = Some(
                        "Please provide a profile name or share link / config file".to_string(),
                    );
                    self.active_modal = ActiveModal::ConfigAdder(adder);
                    return Ok(());
                }

                let mut proxy_endpoint = None;
                let mut derived_name = name.to_string();
                let mut endpoint_str = "127.0.0.1:10808".to_string();

                if !link.is_empty() {
                    if link.starts_with("http://") || link.starts_with("https://") {
                        let folder_name = if let Some(ref g) = group_opt {
                            g.clone()
                        } else if !name.is_empty() {
                            name.to_string()
                        } else {
                            "Subscription".to_string()
                        };

                        match fetch_subscription_feed(link).await {
                            Ok(body) => {
                                let profiles = parse_subscription_profiles(
                                    &body,
                                    &folder_name,
                                    adder.v2_routing_mode,
                                    adder.v2_core,
                                );
                                if profiles.is_empty() {
                                    adder.error_msg = Some(
                                        "No valid proxy nodes found in subscription feed"
                                            .to_string(),
                                    );
                                    self.active_modal = ActiveModal::ConfigAdder(adder);
                                    return Ok(());
                                }

                                if adder.v2_save_as_subscription {
                                    let sub_name = if !name.is_empty() {
                                        name.to_string()
                                    } else {
                                        folder_name.clone()
                                    };
                                    let mut sub = Subscription::new(&sub_name, link, &folder_name)
                                        .with_routing_mode(adder.v2_routing_mode)
                                        .with_core_pref(adder.v2_core);
                                    sub.last_synced = Some(current_timestamp_string());

                                    if let Some(pos) = self
                                        .subscriptions
                                        .iter()
                                        .position(|s| s.url == link || s.id == sub.id)
                                    {
                                        self.subscriptions[pos] = sub;
                                    } else {
                                        self.subscriptions.push(sub);
                                    }
                                    let _ = self.storage.save_subscriptions(&self.subscriptions);
                                }

                                for prof in &profiles {
                                    self.storage.save_profile(prof)?;
                                }
                                self.ensure_custom_folder(&folder_name);
                                self.expanded_folders.insert(folder_name.clone());
                                self.reload_profiles();
                                self.add_log(format!(
                                    "Imported {} proxy profiles from subscription into '{}'.",
                                    profiles.len(),
                                    folder_name
                                ));
                                self.active_modal = ActiveModal::None;
                                return Ok(());
                            }
                            Err(e) => {
                                adder.error_msg =
                                    Some(format!("Failed to fetch subscription: {}", e));
                                self.active_modal = ActiveModal::ConfigAdder(adder);
                                return Ok(());
                            }
                        }
                    }

                    match crate::domain::proxy_link::parse_share_link(link) {
                        Ok((parsed_endpoint, opt_name)) => {
                            endpoint_str =
                                format!("{}:{}", parsed_endpoint.server, parsed_endpoint.port);
                            if derived_name.is_empty() {
                                if let Some(n) = opt_name {
                                    derived_name = n;
                                } else {
                                    derived_name = format!(
                                        "{}-{}",
                                        parsed_endpoint
                                            .protocol_type
                                            .map(|t| t.display_name())
                                            .unwrap_or("Proxy"),
                                        parsed_endpoint.port
                                    );
                                }
                            }
                            proxy_endpoint = Some(parsed_endpoint);
                        }
                        Err(e) => {
                            adder.error_msg = Some(format!("Invalid share link: {}", e));
                            self.active_modal = ActiveModal::ConfigAdder(adder);
                            return Ok(());
                        }
                    }
                }

                if derived_name.is_empty() {
                    if !config_path.is_empty() {
                        let p = std::path::Path::new(config_path);
                        derived_name = p
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("v2ray-config")
                            .to_string();
                    } else {
                        derived_name = "V2Ray Profile".to_string();
                    }
                }

                let cfg_file = if !config_path.is_empty() {
                    Some(std::path::PathBuf::from(config_path))
                } else {
                    None
                };

                let mut prof = Profile::new_v2ray(&derived_name, &endpoint_str, cfg_file)
                    .with_proxy_routing_mode(adder.v2_routing_mode)
                    .with_proxy_core(adder.v2_core);

                if let Some(id) = adder.editing_profile_id.clone() {
                    prof.id = id;
                }
                prof.inherit_defaults = adder.inherit_defaults;
                prof.group = group_opt.clone();
                if let Some(endpoint) = proxy_endpoint {
                    prof.proxy_endpoint = Some(endpoint);
                }
                for f in adder.v2_custom_flags.split_whitespace() {
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

    #[test]
    fn test_app_event_channel_initialization_and_handle_app_event() {
        let mut app = setup_app();
        let pid = app.profiles[0].id.clone();
        assert_eq!(app.profiles[0].latency, LatencyState::Unknown);

        // PingResult updates profile latency
        app.handle_app_event(AppEvent::PingResult {
            profile_id: pid.clone(),
            latency: LatencyState::Measured(42),
        });
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(42));

        // VpnLog appends to logs
        app.handle_app_event(AppEvent::VpnLog(LogEvent::Stdout(
            "test app event log".into(),
        )));
        assert!(app.logs.iter().any(|l| l.contains("test app event log")));

        // Channel sending + poll_log_events
        app.app_event_tx
            .send(AppEvent::PingResult {
                profile_id: pid,
                latency: LatencyState::Measured(99),
            })
            .unwrap();
        app.poll_log_events();
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(99));
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

        app.ping_all();
        assert_eq!(app.profiles[0].latency, LatencyState::Pinging);

        let ev = app.app_event_rx.recv().await.unwrap();
        app.handle_app_event(ev);
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(25));
    }

    #[tokio::test]
    async fn test_app_ping_selected() {
        let mut app = setup_app();
        let prof2 = Profile::new_openconnect("London", "vpn.london.com:443");
        app.storage.save_profile(&prof2).unwrap();
        app.profiles.push(prof2);

        assert_eq!(app.profiles[0].latency, LatencyState::Unknown);
        assert_eq!(app.profiles[1].latency, LatencyState::Unknown);

        app.select_profile_by_idx(0);
        app.ping_selected();

        assert_eq!(app.profiles[0].latency, LatencyState::Pinging);
        assert_eq!(app.profiles[1].latency, LatencyState::Unknown);

        let ev = app.app_event_rx.recv().await.unwrap();
        app.handle_app_event(ev);
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(25));
        assert_eq!(app.profiles[1].latency, LatencyState::Unknown);
    }

    #[tokio::test]
    async fn test_app_ping_selected_folder_noop() {
        let mut app = setup_app();
        app.profiles[0].group = Some("Work/Servers".to_string());
        app.expanded_folders.insert("Work".to_string());
        app.sync_tree_selection();
        app.selected_tree_idx = 0; // Folder node
        app.ping_selected();

        assert_eq!(app.profiles[0].latency, LatencyState::Unknown);
        assert!(app.app_event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_app_ping_keybindings() {
        let mut app = setup_app();
        assert_eq!(app.profiles[0].latency, LatencyState::Unknown);

        app.handle_key(KeyCode::Char('p')).await.unwrap();
        assert_eq!(app.profiles[0].latency, LatencyState::Pinging);
        let ev = app.app_event_rx.recv().await.unwrap();
        app.handle_app_event(ev);
        assert_eq!(app.profiles[0].latency, LatencyState::Measured(25));

        app.profiles[0].latency = LatencyState::Unknown;

        app.handle_key(KeyCode::Char('P')).await.unwrap();
        assert_eq!(app.profiles[0].latency, LatencyState::Pinging);
        let ev = app.app_event_rx.recv().await.unwrap();
        app.handle_app_event(ev);
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

        app.submit_config_adder(adder).await.unwrap();

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
        app.submit_config_adder(adder).await.unwrap();

        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "Strict Profile")
            .unwrap();
        assert_eq!(prof.ssl_policy, SslPolicy::Strict);
    }

    #[tokio::test]
    pub async fn test_app_config_adder_inherit_defaults_toggle() {
        let mut app = setup_app();
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        // Navigate to field 8 (Inherit Defaults for OpenConnect)
        for _ in 0..8 {
            app.handle_key(KeyCode::Tab).await.unwrap();
        }

        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 8);
        assert!(adder.inherit_defaults);

        // Toggle with space -> false
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert!(!adder.inherit_defaults);

        // Toggle with space -> true
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert!(adder.inherit_defaults);
    }

    #[tokio::test]
    pub async fn test_app_config_adder_custom_flags_and_checkboxes() {
        use crossterm::event::KeyCode;

        let mut app = setup_app();
        app.handle_key(KeyCode::Char('n')).await.unwrap();

        // 1. OpenConnect: navigate to field 8 (Inherit Defaults)
        for _ in 0..8 {
            app.handle_key(KeyCode::Tab).await.unwrap();
        }
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 8);
        assert!(adder.inherit_defaults);

        // Toggle with Space: true -> false
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert!(!adder.inherit_defaults);

        // 2. Tab to field 9 (No-DTLS)
        app.handle_key(KeyCode::Tab).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 9);
        assert!(!adder.oc_no_dtls);

        // Toggle with Space
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert!(adder.oc_no_dtls);

        // 3. Tab to field 10 (Custom Flags)
        app.handle_key(KeyCode::Tab).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.field_idx, 10);
        assert!(adder.oc_custom_flags.is_empty());

        // Type "--pfs --mtu=1400"
        for c in "--pfs --mtu=1400".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.oc_custom_flags, "--pfs --mtu=1400");

        // Backspace twice to test backspace on custom flags
        app.handle_key(KeyCode::Backspace).await.unwrap();
        app.handle_key(KeyCode::Backspace).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.oc_custom_flags, "--pfs --mtu=14");

        // Finish typing and submit
        for c in "00".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        let mut adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            other => panic!("Expected ConfigAdder, got {:?}", other),
        };
        assert_eq!(adder.oc_custom_flags, "--pfs --mtu=1400");
        adder.oc_name = "OC Flags Test".into();
        adder.oc_endpoint = "oc.flags.corp:443".into();
        app.submit_config_adder(adder).await.unwrap();

        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "OC Flags Test")
            .unwrap();
        assert!(!prof.inherit_defaults);
        assert!(prof.flags.contains(&"--no-dtls".to_string()));
        assert!(prof.flags.contains(&"--pfs".to_string()));
        assert!(prof.flags.contains(&"--mtu=1400".to_string()));
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

        app.submit_config_adder(adder).await.unwrap();

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
    pub async fn test_app_config_submit_v2ray_valid_and_invalid_links() {
        let mut app = setup_app();

        // 1. Test invalid share link is rejected
        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::V2Ray;
        adder.v2_name = "Bad Link Profile".into();
        adder.v2_link = "invalid://bad-uri".into();

        app.submit_config_adder(adder).await.unwrap();
        match &app.active_modal {
            ActiveModal::ConfigAdder(st) => {
                assert!(st.error_msg.is_some());
                assert!(
                    st.error_msg
                        .as_ref()
                        .unwrap()
                        .contains("Invalid share link")
                );
            }
            other => panic!("Expected ConfigAdder modal with error, got {:?}", other),
        }

        // 2. Test valid VLESS share link is successfully saved
        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::V2Ray;
        adder.v2_name = "Good VLESS".into();
        adder.v2_link = "vless://96c8d350-f80e-4361-9f93-549b6d65c3bb@sg.node.net:443?type=ws&security=reality&sni=sg.node.net#SG-Node".into();
        adder.v2_routing_mode = ProxyRoutingMode::Tun;
        adder.v2_core = ProxyCore::SingBox;

        app.submit_config_adder(adder).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        let prof = app
            .profiles
            .iter()
            .find(|p| p.name == "Good VLESS")
            .expect("V2Ray profile saved");
        assert_eq!(prof.protocol, VpnProtocol::V2Ray);
        assert_eq!(prof.endpoint, "sg.node.net:443");
        assert_eq!(prof.proxy_routing_mode, ProxyRoutingMode::Tun);
        assert_eq!(prof.proxy_core, ProxyCore::SingBox);
        assert!(prof.proxy_endpoint.is_some());
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
        app.submit_config_adder(edited_adder).await.unwrap();

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

        // OpenConnect total_fields = 12
        assert_eq!(adder.total_fields(), 12);

        adder.oc_name = "Production US".to_string();
        adder.oc_endpoint = "vpn.us.corp:443".to_string();
        adder.field_idx = 11; // Group field

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

        // Set field_idx to 11 (Folder field)
        let mut adder = adder;
        adder.oc_name = "Frankfurt Gateway".to_string();
        adder.oc_endpoint = "1.2.3.4:443".to_string();
        adder.field_idx = 11;
        app.active_modal = ActiveModal::ConfigAdder(adder);

        // Press Space on field 11 -> Cycles to index 1: "BioVPN/Cisco"
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        let adder = match &app.active_modal {
            ActiveModal::ConfigAdder(a) => a.clone(),
            _ => panic!("Expected ConfigAdder modal"),
        };
        assert_eq!(adder.folder_option_idx, 1);
        assert_eq!(adder.selected_folder_display(), "BioVPN/Cisco");

        // Press Right on field 11 -> Cycles to index 2: "Work/Europe"
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

        app.active_modal = ActiveModal::SyncManager(SyncManagerState {
            target_account_idx: Some(0),
            ..Default::default()
        });
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

        app.active_modal = ActiveModal::SyncManager(SyncManagerState {
            target_account_idx: Some(0),
            ..Default::default()
        });
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

    #[tokio::test]
    async fn test_subscription_manager_modal_navigation_and_actions() {
        use crossterm::event::KeyCode;

        let mut storage = InMemoryStorage::new();
        let sub = Subscription::new("Initial Sub", "https://mysub.net/feed", "SubFolder");
        storage.save_subscriptions(&[sub]).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'S' to open SyncManager
        app.handle_key(KeyCode::Char('S')).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::SyncManager(_)));

        // Down 3 times to select method 3: [4] V2Ray Subscriptions
        app.handle_key(KeyCode::Down).await.unwrap();
        app.handle_key(KeyCode::Down).await.unwrap();
        app.handle_key(KeyCode::Down).await.unwrap();

        // Hit Enter to enter SubscriptionManager
        app.handle_key(KeyCode::Enter).await.unwrap();
        match &app.active_modal {
            ActiveModal::SubscriptionManager(st) => {
                assert!(!st.is_adding);
                assert_eq!(st.subscriptions.len(), 1);
                assert_eq!(st.subscriptions[0].name, "Initial Sub");
            }
            other => panic!("Expected SubscriptionManager, got {:?}", other),
        }

        // Press 'a' to enter adding mode
        app.handle_key(KeyCode::Char('a')).await.unwrap();
        if let ActiveModal::SubscriptionManager(st) = &app.active_modal {
            assert!(st.is_adding);
            assert_eq!(st.add_field_idx, 0);
        } else {
            panic!("Expected is_adding = true");
        }

        // Cancel adding mode with Esc
        app.handle_key(KeyCode::Esc).await.unwrap();
        if let ActiveModal::SubscriptionManager(st) = &app.active_modal {
            assert!(!st.is_adding);
        }

        // Delete subscription with 'd'
        app.handle_key(KeyCode::Char('d')).await.unwrap();
        if let ActiveModal::SubscriptionManager(st) = &app.active_modal {
            assert_eq!(st.subscriptions.len(), 0);
            assert!(
                st.status_message
                    .as_ref()
                    .unwrap()
                    .contains("Deleted subscription")
            );
        }

        // Press Esc to exit back to SyncManager
        app.handle_key(KeyCode::Esc).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::SyncManager(_)));
    }

    #[tokio::test]
    async fn test_config_adder_v2ray_subscription_mode_toggle() {
        use crossterm::event::KeyCode;

        let mut adder = ConfigAdderState::new(None);
        adder.protocol = VpnProtocol::V2Ray;
        assert_eq!(adder.total_fields(), 8);

        // Setting an HTTP URL expands total_fields to 9
        adder.v2_link = "https://mysub.provider/feed".into();
        assert_eq!(adder.total_fields(), 9);

        // Field 8 is the managed subscription toggle
        adder.field_idx = 8;
        assert!(adder.v2_save_as_subscription);

        // Toggle with Space
        let mut app = setup_app();
        app.active_modal = ActiveModal::ConfigAdder(adder);
        app.handle_key(KeyCode::Char(' ')).await.unwrap();

        if let ActiveModal::ConfigAdder(st) = &app.active_modal {
            assert!(!st.v2_save_as_subscription);
        } else {
            panic!("Expected ConfigAdder modal");
        }
    }

    #[tokio::test]
    async fn test_sync_manager_portal_cycling_and_deletion() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'S' to open SyncManager
        app.handle_key(KeyCode::Char('S')).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.selected_method_idx, 0);
            assert_eq!(st.selected_portal_url(), "https://bio4co.com");
            assert_eq!(st.portal_urls.len(), 2);
        } else {
            panic!("Expected SyncManager modal");
        }

        // Cycle right -> selects https://n1buy.info
        app.handle_key(KeyCode::Right).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.selected_portal_url(), "https://n1buy.info");
        } else {
            panic!("Expected SyncManager modal");
        }

        // Cycle left -> returns to https://bio4co.com
        app.handle_key(KeyCode::Left).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.selected_portal_url(), "https://bio4co.com");
        } else {
            panic!("Expected SyncManager modal");
        }

        // Delete current portal (bio4co.com)
        app.handle_key(KeyCode::Char('d')).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.portal_urls.len(), 1);
            assert_eq!(st.selected_portal_url(), "https://n1buy.info");
        } else {
            panic!("Expected SyncManager modal");
        }

        // Delete only remaining portal (n1buy.info) -> resets to default 2 mirrors!
        app.handle_key(KeyCode::Char('d')).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.portal_urls.len(), 2);
            assert_eq!(st.portal_urls[0], "https://bio4co.com");
            assert_eq!(st.portal_urls[1], "https://n1buy.info");
        } else {
            panic!("Expected SyncManager modal");
        }

        // Verify storage persisted the default portals
        let loaded = app.storage.load_biovpn_portals().unwrap();
        assert_eq!(loaded.urls.len(), 2);
    }

    #[tokio::test]
    async fn test_sync_manager_add_portal_modal_flow() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'S' to open SyncManager
        app.handle_key(KeyCode::Char('S')).await.unwrap();

        // Press 'a' to open AddBioVpnPortal modal
        app.handle_key(KeyCode::Char('a')).await.unwrap();
        assert!(matches!(
            app.active_modal,
            ActiveModal::AddBioVpnPortal { .. }
        ));

        // Type "mirror.org/vpn/"
        for c in "mirror.org/vpn/".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }

        // Hit Enter
        app.handle_key(KeyCode::Enter).await.unwrap();

        // Should return to SyncManager with normalized "https://mirror.org/vpn" active
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.selected_portal_url(), "https://mirror.org/vpn");
            assert_eq!(st.portal_urls.len(), 3);
            assert!(
                st.status_message
                    .as_ref()
                    .unwrap()
                    .contains("Added portal mirror")
            );
        } else {
            panic!("Expected SyncManager modal after adding portal");
        }

        // Verify storage persisted the new portal
        let loaded = app.storage.load_biovpn_portals().unwrap();
        assert_eq!(loaded.selected.as_deref(), Some("https://mirror.org/vpn"));
        assert!(loaded.urls.contains(&"https://mirror.org/vpn".to_string()));
    }

    #[tokio::test]
    async fn test_sync_manager_account_cycling() {
        let mut storage = InMemoryStorage::new();
        let acc1 = Account::new("AccountOne");
        let acc2 = Account::new("AccountTwo");
        storage.save_account(&acc1).unwrap();
        storage.save_account(&acc2).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // Press 'S' to open SyncManager
        app.handle_key(KeyCode::Char('S')).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, Some(0));
        } else {
            panic!("Expected SyncManager modal");
        }

        // Tab -> AccountTwo
        app.handle_key(KeyCode::Tab).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, Some(1));
        }

        // Tab -> None (Unassigned)
        app.handle_key(KeyCode::Tab).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, None);
        }

        // Tab -> AccountOne
        app.handle_key(KeyCode::Tab).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, Some(0));
        }

        // BackTab -> None
        app.handle_key(KeyCode::BackTab).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, None);
        }

        // BackTab -> AccountTwo
        app.handle_key(KeyCode::BackTab).await.unwrap();
        if let ActiveModal::SyncManager(st) = &app.active_modal {
            assert_eq!(st.target_account_idx, Some(1));
        }
    }

    #[tokio::test]
    async fn test_sync_manager_direct_bundle_unassigned() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Create a fake zip in memory
        let fake_zip = {
            let mut buf = Vec::new();
            {
                let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zip.start_file("Frankfurt-SmartTCP.ovpn", options).unwrap();
                use std::io::Write;
                zip.write_all(b"remote 192.168.1.1 1194\nproto udp\n")
                    .unwrap();
                zip.finish().unwrap();
            }
            buf
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\n\r\n",
                    fake_zip.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&fake_zip).await;
            }
        });

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let portal_url = format!("http://{}", local_addr);
        let mut sync_state = SyncManagerState::new();
        sync_state.portal_urls = vec![portal_url];
        sync_state.selected_portal_idx = 0;
        sync_state.target_account_idx = None; // Unassigned!

        app.active_modal = ActiveModal::SyncManager(sync_state);
        app.handle_key(KeyCode::Enter).await.unwrap();
        app.wait_for_sync().await;

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 2); // 1 OpenVPN + 1 Cisco
        assert_eq!(app.profiles[0].account_id, None);
        assert_eq!(app.profiles[1].account_id, None);
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("imported 1 OpenVPN and 1 Cisco"))
        );
    }

    #[tokio::test]
    async fn test_sync_manager_batch_import_unassigned() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let mut sync_state = SyncManagerState::new();
        sync_state.selected_method_idx = 2; // Batch server import
        sync_state.target_account_idx = None; // Unassigned

        app.active_modal = ActiveModal::SyncManager(sync_state);
        app.handle_key(KeyCode::Enter).await.unwrap();

        assert!(matches!(app.active_modal, ActiveModal::BatchInput(_)));

        // Type server entry
        for c in "DirectServer 192.168.10.1:443".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        app.handle_key(KeyCode::Enter).await.unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "DirectServer");
        assert_eq!(app.profiles[0].account_id, None);
    }

    #[tokio::test]
    async fn test_sync_manager_batch_import_html_with_subfolders() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let mut sync_state = SyncManagerState::new();
        sync_state.selected_method_idx = 2; // Batch server import
        sync_state.target_account_idx = None;

        app.active_modal = ActiveModal::SyncManager(sync_state);
        app.handle_key(KeyCode::Enter).await.unwrap();

        let html_input = r#"
            <table class="table">
                <tr class="bio-server-group-toggle"><th>آلمان</th></tr>
                <tr class="bio-server-child-row">
                    <th>Berlin-Cisco</th>
                    <td><span class="server-address">de1.biovpn.net:443</span></td>
                </tr>
            </table>
        "#;

        for c in html_input.chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        app.handle_key(KeyCode::Enter).await.unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "Berlin-Cisco (de1) (Cisco)");
        assert_eq!(
            app.profiles[0].group.as_deref(),
            Some("BioVPN/Cisco/Germany")
        );
        assert!(
            app.custom_folders
                .contains(&"BioVPN/Cisco/Germany".to_string())
        );
        assert!(app.expanded_folders.contains("BioVPN/Cisco/Germany"));
    }

    #[tokio::test]
    async fn test_sync_manager_file_browser_html_import() {
        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        let temp_dir = tempfile::tempdir().unwrap();
        let html_file_path = temp_dir.path().join("dashboard.html");
        let html_content = r#"
            <div id="accordion-tab-regular-2">
                <tr class="bio-server-group-toggle"><th>هلند</th></tr>
                <tr class="bio-server-child-row">
                    <th>Amsterdam-01</th>
                    <td><span class="server-address">nl.cdntak.com</span></td>
                </tr>
            </div>
        "#;
        std::fs::write(&html_file_path, html_content).unwrap();

        let sync_state = SyncManagerState::new();
        let mut browser_state =
            crate::ui::file_picker::FileBrowserState::new(Some(temp_dir.path().to_path_buf()));
        // Select the html file
        let idx = browser_state
            .entries
            .iter()
            .position(|e| e.name == "dashboard.html")
            .unwrap();
        browser_state.selected_index = idx;

        app.active_modal = ActiveModal::SyncFileBrowser {
            state: browser_state,
            sync_state,
        };

        app.handle_key(KeyCode::Enter).await.unwrap();

        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "Amsterdam-01 (nl) (Cisco)");
        assert_eq!(app.profiles[0].endpoint, "nl.cdntak.com:443");
        assert_eq!(
            app.profiles[0].group.as_deref(),
            Some("BioVPN/Cisco/Netherlands")
        );
        assert!(
            app.custom_folders
                .contains(&"BioVPN/Cisco/Netherlands".to_string())
        );
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Imported 1 Cisco profiles"))
        );
    }

    #[tokio::test]
    async fn test_app_delete_openvpn_profile_fs_storage_integration() {
        use crate::infra::fs_storage::FsConfigStorage;
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        // Create an OpenVPN profile with a real file in openvpn dir
        let fake_ovpn = tmp.path().join("source.ovpn");
        std::fs::write(&fake_ovpn, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();
        let prof = storage.import_ovpn(&fake_ovpn, "Production OVPN").unwrap();
        let ovpn_path = prof.ovpn_file.as_ref().unwrap().clone();
        assert!(ovpn_path.exists());

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        assert_eq!(app.profiles.len(), 1);

        // Delete profile via 'x' and 'y'
        app.active_pane = ActivePane::Profiles;
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert!(matches!(
            app.active_modal,
            ActiveModal::ConfirmDelete { .. }
        ));

        app.handle_key(KeyCode::Char('y')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);
        assert_eq!(app.profiles.len(), 0);

        // Verify underlying .ovpn file is deleted from disk
        assert!(!ovpn_path.exists());

        // Reload profiles from storage: MUST NOT resurrect
        app.reload_profiles();
        assert_eq!(app.profiles.len(), 0);
    }

    #[tokio::test]
    async fn test_app_folder_delete_openvpn_profiles_cascade_fs_storage() {
        use crate::infra::fs_storage::FsConfigStorage;
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let ovpn_dir = storage.protocol_dir(VpnProtocol::OpenVpn);
        std::fs::create_dir_all(&ovpn_dir).unwrap();

        // 1. BioVPN profile 1 inside folder "BioVPN/OpenVPN"
        let f1 = ovpn_dir.join("germany.ovpn");
        std::fs::write(&f1, "client\ndev tun\nremote 1.1.1.1 1194").unwrap();
        let p1 = Profile::new_openvpn("germany (OVPN)", "1.1.1.1:1194", Some(f1.clone()))
            .with_group("BioVPN/OpenVPN");
        storage.save_profile(&p1).unwrap();

        // 2. BioVPN profile 2 inside folder "BioVPN/OpenVPN"
        let f2 = ovpn_dir.join("france.ovpn");
        std::fs::write(&f2, "client\ndev tun\nremote 2.2.2.2 1194").unwrap();
        let p2 = Profile::new_openvpn("france (OVPN)", "2.2.2.2:1194", Some(f2.clone()))
            .with_group("BioVPN/OpenVPN");
        storage.save_profile(&p2).unwrap();

        // 3. Standalone profile outside BioVPN folder
        let f3 = ovpn_dir.join("standalone.ovpn");
        std::fs::write(&f3, "client\ndev tun\nremote 3.3.3.3 1194").unwrap();
        let p3 = Profile::new_openvpn("standalone", "3.3.3.3:1194", Some(f3.clone()));
        storage.save_profile(&p3).unwrap();

        storage
            .save_folders(&["BioVPN".to_string(), "BioVPN/OpenVPN".to_string()])
            .unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        app.expanded_folders.insert("BioVPN".to_string());
        app.expanded_folders.insert("BioVPN/OpenVPN".to_string());
        assert_eq!(app.profiles.len(), 3);

        // Find the BioVPN folder node in the tree
        app.active_pane = ActivePane::Profiles;
        let tree = app.visible_tree();
        let biovpn_idx = tree
            .iter()
            .position(|node| match node {
                crate::ui::tree::VisibleTreeNode::Folder { path, .. } => path == "BioVPN",
                _ => false,
            })
            .expect("BioVPN folder node must exist");

        app.selected_tree_idx = biovpn_idx;

        // Press 'x' to initiate folder delete
        app.handle_key(KeyCode::Char('x')).await.unwrap();
        assert!(matches!(
            app.active_modal,
            ActiveModal::ConfirmDelete {
                target: DeleteTarget::Folder { .. }
            }
        ));

        // Confirm delete with 'y'
        app.handle_key(KeyCode::Char('y')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // Verify underlying .ovpn files for BioVPN profiles are deleted from disk!
        assert!(!f1.exists(), "germany.ovpn must be deleted");
        assert!(!f2.exists(), "france.ovpn must be deleted");
        // Standalone file must still exist
        assert!(f3.exists(), "standalone.ovpn must remain intact");

        // Reload profiles: Only standalone profile remains
        app.reload_profiles();
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].name, "standalone");
    }

    #[tokio::test]
    async fn test_defaults_modal_lifecycle_and_keybindings() {
        use crossterm::event::KeyCode;

        let storage = InMemoryStorage::new();
        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());

        // 1. Initial defaults match ProtocolDefaults::default()
        assert_eq!(app.defaults, ProtocolDefaults::default());

        // 2. Cannot open Defaults modal from Accounts pane
        app.active_pane = ActivePane::Accounts;
        app.handle_key(KeyCode::Char('D')).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // 3. Open Defaults modal from Profiles pane via 'D'
        app.active_pane = ActivePane::Profiles;
        app.handle_key(KeyCode::Char('D')).await.unwrap();
        match &app.active_modal {
            ActiveModal::Defaults(st) => {
                assert_eq!(st.field_idx, 0);
                assert_eq!(st.oc_flags, "--protocol=anyconnect --no-dtls --pfs");
                assert_eq!(st.ovpn_flags, "--dev tun --redirect-gateway def1");
            }
            other => panic!("Expected Defaults modal, got {:?}", other),
        }

        // 4. Cancel with Esc
        app.handle_key(KeyCode::Esc).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        // 5. Open Defaults modal from Flags pane via 'D'
        app.active_pane = ActivePane::Flags;
        app.handle_key(KeyCode::Char('D')).await.unwrap();
        assert!(matches!(app.active_modal, ActiveModal::Defaults(_)));

        // 6. Navigation between fields: Tab and BackTab
        app.handle_key(KeyCode::Tab).await.unwrap();
        if let ActiveModal::Defaults(st) = &app.active_modal {
            assert_eq!(st.field_idx, 1);
        } else {
            panic!("Expected Defaults modal");
        }

        app.handle_key(KeyCode::BackTab).await.unwrap();
        if let ActiveModal::Defaults(st) = &app.active_modal {
            assert_eq!(st.field_idx, 0);
        } else {
            panic!("Expected Defaults modal");
        }

        // 7. Edit field 0 (OpenConnect flags): type extra flag
        for c in " --compression=lz4".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        if let ActiveModal::Defaults(st) = &app.active_modal {
            assert_eq!(
                st.oc_flags,
                "--protocol=anyconnect --no-dtls --pfs --compression=lz4"
            );
        }

        // 8. Switch to field 1 (OpenVPN flags) and edit
        app.handle_key(KeyCode::Tab).await.unwrap();
        // Backspace to remove "def1"
        for _ in 0..4 {
            app.handle_key(KeyCode::Backspace).await.unwrap();
        }
        for c in "bypass-dhcp".chars() {
            app.handle_key(KeyCode::Char(c)).await.unwrap();
        }
        if let ActiveModal::Defaults(st) = &app.active_modal {
            assert_eq!(st.ovpn_flags, "--dev tun --redirect-gateway bypass-dhcp");
        }

        // 9. Submit with Enter: persists to storage, updates app.defaults, closes modal
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert_eq!(app.active_modal, ActiveModal::None);

        assert_eq!(
            app.defaults.openconnect_flags,
            vec![
                "--protocol=anyconnect",
                "--no-dtls",
                "--pfs",
                "--compression=lz4"
            ]
        );
        assert_eq!(
            app.defaults.openvpn_flags,
            vec!["--dev", "tun", "--redirect-gateway", "bypass-dhcp"]
        );

        // Verify storage persisted defaults
        let loaded = app.storage.load_defaults().unwrap();
        assert_eq!(loaded, app.defaults);
    }

    #[tokio::test]
    async fn test_toggle_selected_profile_inheritance_hotkeys() {
        use crossterm::event::KeyCode;

        let mut storage = InMemoryStorage::new();
        let prof = Profile::new_openconnect("Test Gateway", "vpn.test:443")
            .with_inherit_defaults(true);
        storage.save_profile(&prof).unwrap();

        let mut app = App::new(storage, MockVpnRunner::new(), MockPinger::new());
        assert_eq!(app.profiles.len(), 1);
        assert!(app.profiles[0].inherit_defaults);

        // 1. From Profiles pane: press 'i' to toggle inheritance off
        app.active_pane = ActivePane::Profiles;
        app.handle_key(KeyCode::Char('i')).await.unwrap();
        assert!(!app.profiles[0].inherit_defaults);

        // Verify storage persisted updated profile
        let loaded = app.storage.load_profiles(None).unwrap();
        assert!(!loaded[0].inherit_defaults);

        // 2. From Profiles pane: press 'I' to toggle inheritance back on
        app.handle_key(KeyCode::Char('I')).await.unwrap();
        assert!(app.profiles[0].inherit_defaults);

        // 3. Switch to Flags pane: press Space to toggle off
        app.active_pane = ActivePane::Flags;
        app.handle_key(KeyCode::Char(' ')).await.unwrap();
        assert!(!app.profiles[0].inherit_defaults);

        // 4. From Flags pane: press Enter to toggle back on
        app.handle_key(KeyCode::Enter).await.unwrap();
        assert!(app.profiles[0].inherit_defaults);
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
