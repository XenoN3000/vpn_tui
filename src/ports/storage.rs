use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, VpnProtocol};
use crate::domain::subscription::Subscription;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BioVpnPortalsConfig {
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
}

impl Default for BioVpnPortalsConfig {
    fn default() -> Self {
        Self {
            selected: Some("https://bio4co.com".to_string()),
            urls: vec![
                "https://bio4co.com".to_string(),
                "https://n1buy.info".to_string(),
            ],
        }
    }
}

impl BioVpnPortalsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalizes a portal URL by trimming whitespace and trailing slashes,
    /// and auto-prefixing with https:// if no scheme is provided.
    pub fn normalize_url(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let no_trailing = trimmed.trim_end_matches('/');
        if no_trailing.is_empty() {
            return None;
        }
        if no_trailing.starts_with("http://") || no_trailing.starts_with("https://") {
            Some(no_trailing.to_string())
        } else {
            Some(format!("https://{}", no_trailing))
        }
    }

    /// Adds a new URL after normalization if not already present.
    /// Sets the added or existing URL as selected.
    /// Returns true if added, false if invalid.
    pub fn add_url(&mut self, raw: &str) -> bool {
        let Some(norm) = Self::normalize_url(raw) else {
            return false;
        };
        if !self.urls.contains(&norm) {
            self.urls.push(norm.clone());
        }
        self.selected = Some(norm);
        true
    }

    /// Deletes a URL. If the resulting list is empty, restores default seeds.
    pub fn delete_url(&mut self, url: &str) -> bool {
        let initial_len = self.urls.len();
        self.urls.retain(|u| u != url);
        if self.urls.len() == initial_len {
            return false;
        }
        if self.urls.is_empty() {
            let def = Self::default();
            self.urls = def.urls;
            self.selected = def.selected;
        } else if self.selected.as_deref() == Some(url) {
            self.selected = self.urls.first().cloned();
        }
        true
    }

    /// Returns the currently active URL, or falls back to the first URL or default.
    pub fn active_url(&self) -> String {
        self.selected
            .clone()
            .or_else(|| self.urls.first().cloned())
            .unwrap_or_else(|| "https://bio4co.com".to_string())
    }
}

pub trait ConfigStorage: Send + Sync {
    fn load_accounts(&self) -> Result<Vec<Account>>;
    fn save_account(&mut self, account: &Account) -> Result<()>;
    fn delete_account(&mut self, id: &AccountId) -> Result<bool>;

    fn load_profiles(&self, protocol: Option<VpnProtocol>) -> Result<Vec<Profile>>;
    fn save_profile(&mut self, profile: &Profile) -> Result<()>;
    fn delete_profile(&mut self, id: &ProfileId) -> Result<bool>;

    fn import_ovpn(&mut self, src_path: &Path, name: &str) -> Result<Profile>;
    fn get_config_root(&self) -> PathBuf;

    fn load_folders(&self) -> Result<Vec<String>>;
    fn save_folders(&mut self, folders: &[String]) -> Result<()>;

    fn load_subscriptions(&self) -> Result<Vec<Subscription>>;
    fn save_subscriptions(&mut self, subscriptions: &[Subscription]) -> Result<()>;

    fn load_biovpn_portals(&self) -> Result<BioVpnPortalsConfig>;
    fn save_biovpn_portals(&mut self, config: &BioVpnPortalsConfig) -> Result<()>;
}

/// In-memory mock storage for unit testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStorage {
    pub root: PathBuf,
    pub accounts: HashMap<AccountId, Account>,
    pub profiles: HashMap<ProfileId, Profile>,
    pub folders: Vec<String>,
    pub subscriptions: Vec<Subscription>,
    pub biovpn_portals: Option<BioVpnPortalsConfig>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/mock/config"),
            accounts: HashMap::new(),
            profiles: HashMap::new(),
            folders: Vec::new(),
            subscriptions: Vec::new(),
            biovpn_portals: None,
        }
    }
}

impl ConfigStorage for InMemoryStorage {
    fn load_accounts(&self) -> Result<Vec<Account>> {
        let mut list: Vec<Account> = self.accounts.values().cloned().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    fn save_account(&mut self, account: &Account) -> Result<()> {
        self.accounts.insert(account.id.clone(), account.clone());
        Ok(())
    }

    fn delete_account(&mut self, id: &AccountId) -> Result<bool> {
        Ok(self.accounts.remove(id).is_some())
    }

    fn load_profiles(&self, protocol: Option<VpnProtocol>) -> Result<Vec<Profile>> {
        let mut list: Vec<Profile> = self
            .profiles
            .values()
            .filter(|p| protocol.is_none_or(|proto| p.protocol == proto))
            .cloned()
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    fn save_profile(&mut self, profile: &Profile) -> Result<()> {
        self.profiles.insert(profile.id.clone(), profile.clone());
        Ok(())
    }

    fn delete_profile(&mut self, id: &ProfileId) -> Result<bool> {
        Ok(self.profiles.remove(id).is_some())
    }

    fn import_ovpn(&mut self, src_path: &Path, name: &str) -> Result<Profile> {
        if !src_path.exists() && src_path != Path::new("/mock/test.ovpn") {
            return Err(anyhow!("Source file not found: {:?}", src_path));
        }
        let profile = Profile::new_openvpn(name, "imported:1194", Some(src_path.to_path_buf()));
        self.save_profile(&profile)?;
        Ok(profile)
    }

    fn get_config_root(&self) -> PathBuf {
        self.root.clone()
    }

    fn load_folders(&self) -> Result<Vec<String>> {
        Ok(self.folders.clone())
    }

    fn save_folders(&mut self, folders: &[String]) -> Result<()> {
        self.folders = folders.to_vec();
        Ok(())
    }

    fn load_subscriptions(&self) -> Result<Vec<Subscription>> {
        Ok(self.subscriptions.clone())
    }

    fn save_subscriptions(&mut self, subscriptions: &[Subscription]) -> Result<()> {
        self.subscriptions = subscriptions.to_vec();
        Ok(())
    }

    fn load_biovpn_portals(&self) -> Result<BioVpnPortalsConfig> {
        Ok(self.biovpn_portals.clone().unwrap_or_default())
    }

    fn save_biovpn_portals(&mut self, config: &BioVpnPortalsConfig) -> Result<()> {
        self.biovpn_portals = Some(config.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_storage_subscription_crud() {
        let mut storage = InMemoryStorage::new();
        assert_eq!(storage.load_subscriptions().unwrap().len(), 0);

        let sub = Subscription::new("Sub 1", "https://sub.url", "Folder 1");
        storage.save_subscriptions(&[sub.clone()]).unwrap();

        let subs = storage.load_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].name, "Sub 1");
    }

    #[test]
    fn test_in_memory_storage_account_crud() {
        let mut storage = InMemoryStorage::new();
        assert_eq!(storage.load_accounts().unwrap().len(), 0);

        let acc = Account::new("Work");
        storage.save_account(&acc).unwrap();

        let accounts = storage.load_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "Work");

        let deleted = storage.delete_account(&acc.id).unwrap();
        assert!(deleted);
        assert_eq!(storage.load_accounts().unwrap().len(), 0);
    }

    #[test]
    fn test_in_memory_storage_profile_crud_and_filter() {
        let mut storage = InMemoryStorage::new();

        let p1 = Profile::new_openconnect("Cisco 1", "vpn1.com:443");
        let p2 = Profile::new_openvpn("OpenVPN 1", "vpn2.com:1194", None);

        storage.save_profile(&p1).unwrap();
        storage.save_profile(&p2).unwrap();

        assert_eq!(storage.load_profiles(None).unwrap().len(), 2);
        assert_eq!(
            storage
                .load_profiles(Some(VpnProtocol::OpenConnect))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage
                .load_profiles(Some(VpnProtocol::OpenVpn))
                .unwrap()
                .len(),
            1
        );

        storage.delete_profile(&p1.id).unwrap();
        assert_eq!(storage.load_profiles(None).unwrap().len(), 1);
    }

    #[test]
    fn test_in_memory_storage_import_ovpn() {
        let mut storage = InMemoryStorage::new();
        let profile = storage
            .import_ovpn(Path::new("/mock/test.ovpn"), "Imported Home")
            .unwrap();

        assert_eq!(profile.name, "Imported Home");
        assert_eq!(profile.protocol, VpnProtocol::OpenVpn);
        assert_eq!(storage.load_profiles(None).unwrap().len(), 1);
    }

    #[test]
    fn test_in_memory_storage_folders() {
        let mut storage = InMemoryStorage::new();
        assert_eq!(storage.load_folders().unwrap().len(), 0);

        let folders = vec!["Work/Europe".to_string(), "BioVPN/Cisco".to_string()];
        storage.save_folders(&folders).unwrap();

        let loaded = storage.load_folders().unwrap();
        assert_eq!(loaded, folders);
    }

    #[test]
    fn test_in_memory_storage_biovpn_portals() {
        let mut storage = InMemoryStorage::new();
        let default_config = storage.load_biovpn_portals().unwrap();
        assert_eq!(default_config, BioVpnPortalsConfig::default());

        let custom = BioVpnPortalsConfig {
            selected: Some("https://n1buy.info".to_string()),
            urls: vec!["https://n1buy.info".to_string()],
        };
        storage.save_biovpn_portals(&custom).unwrap();
        assert_eq!(storage.load_biovpn_portals().unwrap(), custom);
    }

    #[test]
    fn test_biovpn_portals_config_helpers() {
        assert_eq!(BioVpnPortalsConfig::normalize_url("   "), None);
        assert_eq!(BioVpnPortalsConfig::normalize_url("///"), None);
        assert_eq!(
            BioVpnPortalsConfig::normalize_url("n1buy.info"),
            Some("https://n1buy.info".to_string())
        );
        assert_eq!(
            BioVpnPortalsConfig::normalize_url("http://mirror.org/path/"),
            Some("http://mirror.org/path".to_string())
        );

        let mut config = BioVpnPortalsConfig::default();
        assert_eq!(config.active_url(), "https://bio4co.com");

        // Add URL
        assert!(config.add_url("  newportal.io/ "));
        assert_eq!(config.active_url(), "https://newportal.io");
        assert!(config.urls.contains(&"https://newportal.io".to_string()));

        // Delete URL
        assert!(config.delete_url("https://newportal.io"));
        assert_ne!(config.active_url(), "https://newportal.io");

        // Delete all -> resets to default
        config.delete_url("https://bio4co.com");
        config.delete_url("https://n1buy.info");
        assert_eq!(config, BioVpnPortalsConfig::default());
    }
}
