use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, ProtocolDefaults, VpnProtocol};
use crate::domain::subscription::Subscription;
use crate::ports::storage::{BioVpnPortalsConfig, ConfigStorage};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AccountsManifest {
    #[serde(default)]
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FoldersManifest {
    #[serde(default)]
    pub folders: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SubscriptionsManifest {
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

#[derive(Debug, Clone)]
pub struct FsConfigStorage {
    root: PathBuf,
}

impl Default for FsConfigStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl FsConfigStorage {
    /// Detects configuration root directory.
    /// Checks `./configs` first, then `~/.config/vpn-tui/`, falling back to legacy `~/.config/bio-vpn-tui/`.
    pub fn new() -> Self {
        let local_configs = PathBuf::from("./configs");
        let root = if local_configs.is_dir() {
            local_configs
        } else {
            let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
                PathBuf::from(xdg)
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".config")
            } else {
                PathBuf::from("./configs")
            };

            let primary = base.join("vpn-tui");
            let legacy = base.join("bio-vpn-tui");
            if !primary.is_dir() && legacy.is_dir() {
                legacy
            } else {
                primary
            }
        };

        Self { root }
    }

    /// Explicit root for custom paths and testing.
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn protocol_dir(&self, protocol: VpnProtocol) -> PathBuf {
        self.root.join(protocol.dir_name())
    }

    pub fn accounts_file(&self) -> PathBuf {
        self.root.join("accounts.toml")
    }

    pub fn folders_file(&self) -> PathBuf {
        self.root.join("folders.toml")
    }

    pub fn subscriptions_file(&self) -> PathBuf {
        self.root.join("subscriptions.toml")
    }

    pub fn biovpn_portals_file(&self) -> PathBuf {
        self.root.join("biovpn_portals.toml")
    }

    pub fn defaults_file(&self) -> PathBuf {
        self.root.join("defaults.toml")
    }

    pub fn is_managed_path(&self, path: &Path) -> bool {
        let canonical_root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        canonical_path.starts_with(&canonical_root)
    }

    fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("Failed to create config root {:?}", self.root))?;
        fs::create_dir_all(self.protocol_dir(VpnProtocol::OpenConnect))?;
        fs::create_dir_all(self.protocol_dir(VpnProtocol::OpenVpn))?;
        fs::create_dir_all(self.protocol_dir(VpnProtocol::V2Ray))?;
        Ok(())
    }
}

impl ConfigStorage for FsConfigStorage {
    fn load_accounts(&self) -> Result<Vec<Account>> {
        let file = self.accounts_file();
        if !file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read accounts file {:?}", file))?;
        let manifest: AccountsManifest = toml::from_str(&content)
            .with_context(|| format!("Failed to parse accounts file {:?}", file))?;
        Ok(manifest.accounts)
    }

    fn save_account(&mut self, account: &Account) -> Result<()> {
        self.ensure_dirs()?;
        let mut accounts = self.load_accounts().unwrap_or_default();
        if let Some(pos) = accounts.iter().position(|a| a.id == account.id) {
            accounts[pos] = account.clone();
        } else {
            accounts.push(account.clone());
        }
        let manifest = AccountsManifest { accounts };
        let serialized = toml::to_string_pretty(&manifest)?;
        fs::write(self.accounts_file(), serialized)?;
        Ok(())
    }

    fn delete_account(&mut self, id: &AccountId) -> Result<bool> {
        let mut accounts = self.load_accounts()?;
        let initial_len = accounts.len();
        accounts.retain(|a| a.id != *id);
        if accounts.len() < initial_len {
            let manifest = AccountsManifest { accounts };
            let serialized = toml::to_string_pretty(&manifest)?;
            fs::write(self.accounts_file(), serialized)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn load_profiles(&self, protocol: Option<VpnProtocol>) -> Result<Vec<Profile>> {
        let mut profiles = Vec::new();

        let protocols: Vec<VpnProtocol> = match protocol {
            Some(p) => vec![p],
            None => vec![
                VpnProtocol::OpenConnect,
                VpnProtocol::OpenVpn,
                VpnProtocol::V2Ray,
            ],
        };

        for proto in protocols {
            let dir = self.protocol_dir(proto);
            if !dir.is_dir() {
                continue;
            }

            let entries = match fs::read_dir(&dir) {
                Ok(rd) => rd.filter_map(|e| e.ok()).collect::<Vec<_>>(),
                Err(_) => continue,
            };

            // First pass: load all TOML descriptors
            for entry in &entries {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(profile) = toml::from_str::<Profile>(&content) {
                            profiles.push(profile);
                        }
                    }
                }
            }

            // Second pass: auto-detect standalone .ovpn / .json files not referenced by any TOML
            for entry in &entries {
                let path = entry.path();
                if path.is_file() {
                    if proto == VpnProtocol::OpenVpn
                        && path.extension().is_some_and(|ext| ext == "ovpn")
                    {
                        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                        let has_companion_toml = path.with_extension("toml").exists();
                        let already_loaded = profiles.iter().any(|p| {
                            p.id.0 == stem
                                || p.ovpn_file.as_ref().is_some_and(|f| {
                                    f == &path || f.canonicalize().ok() == path.canonicalize().ok()
                                })
                        });
                        if !has_companion_toml && !already_loaded {
                            let profile = Profile::new_openvpn(
                                stem.to_string(),
                                "auto-detected",
                                Some(path.clone()),
                            );
                            profiles.push(profile);
                        }
                    } else if proto == VpnProtocol::V2Ray
                        && path.extension().is_some_and(|ext| ext == "json")
                    {
                        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                        let has_companion_toml = path.with_extension("toml").exists();
                        let already_loaded = profiles.iter().any(|p| {
                            p.id.0 == stem
                                || p.proxy_config_file.as_ref().is_some_and(|f| {
                                    f == &path || f.canonicalize().ok() == path.canonicalize().ok()
                                })
                        });
                        if !has_companion_toml && !already_loaded {
                            let profile = Profile::new_v2ray(
                                stem.to_string(),
                                "custom-json",
                                Some(path.clone()),
                            );
                            profiles.push(profile);
                        }
                    }
                }
            }
        }

        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    fn save_profile(&mut self, profile: &Profile) -> Result<()> {
        self.ensure_dirs()?;
        let dir = self.protocol_dir(profile.protocol);
        let file_path = dir.join(format!("{}.toml", profile.id.0));
        let content = toml::to_string_pretty(profile)?;
        fs::write(file_path, content)?;
        Ok(())
    }

    fn delete_profile(&mut self, id: &ProfileId) -> Result<bool> {
        let mut removed = false;
        for proto in [
            VpnProtocol::OpenConnect,
            VpnProtocol::OpenVpn,
            VpnProtocol::V2Ray,
        ] {
            let dir = self.protocol_dir(proto);
            let toml_file = dir.join(format!("{}.toml", id.0));
            if toml_file.exists() {
                if let Ok(content) = fs::read_to_string(&toml_file) {
                    if let Ok(profile) = toml::from_str::<Profile>(&content) {
                        if let Some(ref ovpn_path) = profile.ovpn_file {
                            if self.is_managed_path(ovpn_path) && ovpn_path.exists() {
                                let _ = fs::remove_file(ovpn_path);
                            }
                        }
                        if let Some(ref v2_path) = profile.proxy_config_file {
                            if self.is_managed_path(v2_path) && v2_path.exists() {
                                let _ = fs::remove_file(v2_path);
                            }
                        }
                    }
                }
                fs::remove_file(&toml_file)?;
                removed = true;
            }
            if proto == VpnProtocol::OpenVpn {
                let ovpn_file = dir.join(format!("{}.ovpn", id.0));
                if ovpn_file.exists() {
                    let _ = fs::remove_file(ovpn_file);
                    removed = true;
                }
            }
            if proto == VpnProtocol::V2Ray {
                let json_file = dir.join(format!("{}.json", id.0));
                if json_file.exists() {
                    let _ = fs::remove_file(json_file);
                    removed = true;
                }
            }

            if dir.exists() {
                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if proto == VpnProtocol::OpenVpn
                                && path.extension().is_some_and(|ext| ext == "ovpn")
                            {
                                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                                let slug = stem
                                    .to_lowercase()
                                    .replace(' ', "-")
                                    .chars()
                                    .filter(|c| c.is_alphanumeric() || *c == '-')
                                    .collect::<String>();
                                if stem == id.0 || slug == id.0 || stem.eq_ignore_ascii_case(&id.0)
                                {
                                    let _ = fs::remove_file(&path);
                                    removed = true;
                                }
                            } else if proto == VpnProtocol::V2Ray
                                && path.extension().is_some_and(|ext| ext == "json")
                            {
                                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                                let slug = stem
                                    .to_lowercase()
                                    .replace(' ', "-")
                                    .chars()
                                    .filter(|c| c.is_alphanumeric() || *c == '-')
                                    .collect::<String>();
                                if stem == id.0 || slug == id.0 || stem.eq_ignore_ascii_case(&id.0)
                                {
                                    let _ = fs::remove_file(&path);
                                    removed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(removed)
    }

    fn import_ovpn(&mut self, src_path: &Path, name: &str) -> Result<Profile> {
        self.ensure_dirs()?;
        if !src_path.is_file() {
            anyhow::bail!("Source .ovpn file does not exist: {:?}", src_path);
        }

        let clean_name = name
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();

        let dest_filename = format!("{}.ovpn", clean_name);
        let dest_path = self.protocol_dir(VpnProtocol::OpenVpn).join(&dest_filename);

        fs::copy(src_path, &dest_path)
            .with_context(|| format!("Failed to copy {:?} to {:?}", src_path, dest_path))?;

        let profile = Profile::new_openvpn(name, "imported", Some(dest_path));
        self.save_profile(&profile)?;
        Ok(profile)
    }

    fn get_config_root(&self) -> PathBuf {
        self.root.clone()
    }

    fn load_folders(&self) -> Result<Vec<String>> {
        let file = self.folders_file();
        if !file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read folders file {:?}", file))?;
        let manifest: FoldersManifest = toml::from_str(&content)
            .with_context(|| format!("Failed to parse folders file {:?}", file))?;
        Ok(manifest.folders)
    }

    fn save_folders(&mut self, folders: &[String]) -> Result<()> {
        self.ensure_dirs()?;
        let manifest = FoldersManifest {
            folders: folders.to_vec(),
        };
        let serialized = toml::to_string_pretty(&manifest)?;
        fs::write(self.folders_file(), serialized)?;
        Ok(())
    }

    fn load_subscriptions(&self) -> Result<Vec<Subscription>> {
        let file = self.subscriptions_file();
        if !file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read subscriptions file {:?}", file))?;
        let manifest: SubscriptionsManifest = toml::from_str(&content)
            .with_context(|| format!("Failed to parse subscriptions file {:?}", file))?;
        Ok(manifest.subscriptions)
    }

    fn save_subscriptions(&mut self, subscriptions: &[Subscription]) -> Result<()> {
        self.ensure_dirs()?;
        let manifest = SubscriptionsManifest {
            subscriptions: subscriptions.to_vec(),
        };
        let serialized = toml::to_string_pretty(&manifest)?;
        fs::write(self.subscriptions_file(), serialized)?;
        Ok(())
    }

    fn load_biovpn_portals(&self) -> Result<BioVpnPortalsConfig> {
        let file = self.biovpn_portals_file();
        if !file.exists() {
            return Ok(BioVpnPortalsConfig::default());
        }

        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read BioVPN portals file {:?}", file))?;
        let config: BioVpnPortalsConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse BioVPN portals file {:?}", file))?;
        Ok(config)
    }

    fn save_biovpn_portals(&mut self, config: &BioVpnPortalsConfig) -> Result<()> {
        self.ensure_dirs()?;
        let serialized = toml::to_string_pretty(config)?;
        fs::write(self.biovpn_portals_file(), serialized)?;
        Ok(())
    }

    fn load_defaults(&self) -> Result<ProtocolDefaults> {
        let file = self.defaults_file();
        if !file.exists() {
            return Ok(ProtocolDefaults::default());
        }

        let content = fs::read_to_string(&file)
            .with_context(|| format!("Failed to read defaults file {:?}", file))?;
        let defaults: ProtocolDefaults = toml::from_str(&content)
            .with_context(|| format!("Failed to parse defaults file {:?}", file))?;
        Ok(defaults)
    }

    fn save_defaults(&mut self, defaults: &ProtocolDefaults) -> Result<()> {
        self.ensure_dirs()?;
        let serialized = toml::to_string_pretty(defaults)?;
        fs::write(self.defaults_file(), serialized)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_fs_storage_account_lifecycle() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        assert_eq!(storage.load_accounts().unwrap().len(), 0);

        let acc = Account::new("Test Corp");
        storage.save_account(&acc).unwrap();

        let loaded = storage.load_accounts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Test Corp");

        let deleted = storage.delete_account(&acc.id).unwrap();
        assert!(deleted);
        assert_eq!(storage.load_accounts().unwrap().len(), 0);
    }

    #[test]
    fn test_fs_storage_openconnect_profile_save_load() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let profile =
            Profile::new_openconnect("Office Gateway", "vpn.office.com:443").with_flag("--no-dtls");

        storage.save_profile(&profile).unwrap();

        let profiles = storage
            .load_profiles(Some(VpnProtocol::OpenConnect))
            .unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "Office Gateway");
        assert_eq!(profiles[0].endpoint, "vpn.office.com:443");
        assert_eq!(profiles[0].flags, vec!["--no-dtls"]);
    }

    #[test]
    fn test_fs_storage_import_ovpn_file() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let fake_ovpn = tmp.path().join("source_vpn.ovpn");
        fs::write(&fake_ovpn, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();

        let imported = storage.import_ovpn(&fake_ovpn, "My Home VPN").unwrap();
        assert_eq!(imported.name, "My Home VPN");
        assert_eq!(imported.protocol, VpnProtocol::OpenVpn);
        assert!(imported.ovpn_file.is_some());

        let loaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "My Home VPN");
    }

    #[test]
    fn test_fs_storage_path_resolution() {
        let storage = FsConfigStorage::new();
        let root = storage.get_config_root();
        assert!(!root.as_os_str().is_empty());
    }

    #[test]
    fn test_fs_storage_profile_group_persistence() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let profile =
            Profile::new_openconnect("Munich DC", "10.0.0.1:443").with_group("BioVPN/Cisco/Europe");

        storage.save_profile(&profile).unwrap();

        let loaded = storage.load_profiles(None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].group.as_deref(), Some("BioVPN/Cisco/Europe"));
    }

    #[test]
    fn test_fs_storage_folders_persistence() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        assert_eq!(storage.load_folders().unwrap().len(), 0);

        let folders = vec![
            "BioVPN/Cisco".to_string(),
            "BioVPN/OpenVPN".to_string(),
            "Work/Europe/Munich".to_string(),
        ];
        storage.save_folders(&folders).unwrap();

        // Check file exists on disk and loads back identically
        assert!(storage.folders_file().exists());
        let loaded = storage.load_folders().unwrap();
        assert_eq!(loaded, folders);
    }

    #[test]
    fn test_fs_storage_v2ray_profile_and_json_detection() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let v2_profile = Profile::new_v2ray("Tokyo V2", "tokyo.proxy.net:443", None);
        storage.save_profile(&v2_profile).unwrap();

        let loaded = storage.load_profiles(Some(VpnProtocol::V2Ray)).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Tokyo V2");
        assert_eq!(loaded[0].protocol, VpnProtocol::V2Ray);

        // Also test auto-detecting a standalone .json config in v2ray dir
        let v2_dir = storage.protocol_dir(VpnProtocol::V2Ray);
        let raw_json = v2_dir.join("standalone-server.json");
        fs::write(&raw_json, "{\"inbounds\":[], \"outbounds\":[]}").unwrap();

        let loaded_all = storage.load_profiles(Some(VpnProtocol::V2Ray)).unwrap();
        assert_eq!(loaded_all.len(), 2);
        assert!(loaded_all.iter().any(|p| p.name == "standalone-server"));

        let deleted = storage.delete_profile(&v2_profile.id).unwrap();
        assert!(deleted);
        let remaining = storage.load_profiles(Some(VpnProtocol::V2Ray)).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "standalone-server");
    }

    #[test]
    fn test_fs_storage_subscription_lifecycle() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        assert_eq!(storage.load_subscriptions().unwrap().len(), 0);

        let sub1 = Subscription::new("Sub Alpha", "https://alpha.com/sub", "AlphaFolder");
        let sub2 = Subscription::new("Sub Beta", "https://beta.com/sub", "BetaFolder");
        storage
            .save_subscriptions(&[sub1.clone(), sub2.clone()])
            .unwrap();

        assert!(storage.subscriptions_file().exists());
        let loaded = storage.load_subscriptions().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "Sub Alpha");
        assert_eq!(loaded[1].name, "Sub Beta");

        // Overwrite / update
        storage.save_subscriptions(&[sub1]).unwrap();
        let updated = storage.load_subscriptions().unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].name, "Sub Alpha");
    }

    #[test]
    fn test_fs_storage_biovpn_portals_lifecycle() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        // Default when file does not exist
        let default_config = storage.load_biovpn_portals().unwrap();
        assert_eq!(default_config, BioVpnPortalsConfig::default());
        assert_eq!(
            default_config.urls,
            vec![
                "https://bio4co.com".to_string(),
                "https://n1buy.info".to_string(),
            ]
        );

        let custom = BioVpnPortalsConfig {
            selected: Some("https://n1buy.info".to_string()),
            urls: vec![
                "https://bio4co.com".to_string(),
                "https://n1buy.info".to_string(),
                "https://mirror3.net".to_string(),
            ],
        };
        storage.save_biovpn_portals(&custom).unwrap();
        assert!(storage.biovpn_portals_file().exists());

        let loaded = storage.load_biovpn_portals().unwrap();
        assert_eq!(loaded, custom);
    }

    #[test]
    fn test_fs_storage_delete_openvpn_profile_cleans_managed_file() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        let fake_ovpn = tmp.path().join("source.ovpn");
        fs::write(&fake_ovpn, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();

        let imported = storage.import_ovpn(&fake_ovpn, "Test OpenVPN").unwrap();
        let ovpn_file = imported.ovpn_file.as_ref().unwrap().clone();
        assert!(ovpn_file.exists());

        let loaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(loaded.len(), 1);

        // Delete profile
        let deleted = storage.delete_profile(&imported.id).unwrap();
        assert!(deleted);

        // Check both toml and ovpn are deleted
        assert!(!ovpn_file.exists());
        let reloaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(reloaded.len(), 0);
    }

    #[test]
    fn test_fs_storage_defaults_lifecycle() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());

        // Initial load without file returns defaults
        let def = storage.load_defaults().unwrap();
        assert_eq!(def, ProtocolDefaults::default());

        // Save customized defaults
        let mut custom = ProtocolDefaults::default();
        custom.openconnect_flags.push("--test-flag".into());
        storage.save_defaults(&custom).unwrap();

        assert!(storage.defaults_file().exists());
        let loaded = storage.load_defaults().unwrap();
        assert_eq!(loaded, custom);
    }

    #[test]
    fn test_fs_storage_delete_biovpn_synced_profile_with_different_slug() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());
        storage.ensure_dirs().unwrap();

        // BioVPN creates a file named "de-frankfurt.ovpn"
        let ovpn_dir = storage.protocol_dir(VpnProtocol::OpenVpn);
        let ovpn_file = ovpn_dir.join("de-frankfurt.ovpn");
        fs::write(&ovpn_file, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();

        // But the profile is named "de-frankfurt (OVPN)" with slug "de-frankfurt-ovpn"
        let profile = Profile::new_openvpn(
            "de-frankfurt (OVPN)",
            "1.2.3.4:1194",
            Some(ovpn_file.clone()),
        )
        .with_group("BioVPN/OpenVPN");
        assert_eq!(profile.id.0, "de-frankfurt-ovpn");

        storage.save_profile(&profile).unwrap();

        let loaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "de-frankfurt (OVPN)");

        // Deleting the profile by ID must delete "de-frankfurt.ovpn"
        let deleted = storage.delete_profile(&profile.id).unwrap();
        assert!(deleted);
        assert!(!ovpn_file.exists(), "Underlying .ovpn file must be removed");

        // Reload must NOT resurrect the profile
        let reloaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(reloaded.len(), 0, "Deleted profile must not be resurrected");
    }

    #[test]
    fn test_fs_storage_delete_profile_preserves_external_file() {
        let tmp_storage = tempdir().unwrap();
        let tmp_external = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp_storage.path());

        // File located outside config root
        let external_ovpn = tmp_external.path().join("external_config.ovpn");
        fs::write(&external_ovpn, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();

        let profile = Profile::new_openvpn(
            "External Profile",
            "1.2.3.4:1194",
            Some(external_ovpn.clone()),
        );
        storage.save_profile(&profile).unwrap();

        let loaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(loaded.len(), 1);

        // Delete profile
        let deleted = storage.delete_profile(&profile.id).unwrap();
        assert!(deleted);

        // External file MUST still exist!
        assert!(
            external_ovpn.exists(),
            "External file outside managed root must be preserved"
        );

        let reloaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(reloaded.len(), 0);
    }

    #[test]
    fn test_fs_storage_delete_auto_detected_openvpn_profile() {
        let tmp = tempdir().unwrap();
        let mut storage = FsConfigStorage::with_root(tmp.path());
        storage.ensure_dirs().unwrap();

        // Drop a standalone .ovpn file without any companion .toml
        let ovpn_dir = storage.protocol_dir(VpnProtocol::OpenVpn);
        let standalone_file = ovpn_dir.join("My_Company_Server.ovpn");
        fs::write(&standalone_file, "client\ndev tun\nremote 1.2.3.4 1194").unwrap();

        // Load profiles: auto-detects it
        let loaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(loaded.len(), 1);
        let detected = &loaded[0];
        assert_eq!(detected.id.0, "mycompanyserver");

        // Delete auto-detected profile
        let deleted = storage.delete_profile(&detected.id).unwrap();
        assert!(deleted);
        assert!(
            !standalone_file.exists(),
            "Standalone .ovpn file must be deleted"
        );

        // Reload must find 0 profiles
        let reloaded = storage.load_profiles(Some(VpnProtocol::OpenVpn)).unwrap();
        assert_eq!(reloaded.len(), 0);
    }
}
