use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, VpnProtocol};
use crate::ports::storage::ConfigStorage;
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

    fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("Failed to create config root {:?}", self.root))?;
        fs::create_dir_all(self.protocol_dir(VpnProtocol::OpenConnect))?;
        fs::create_dir_all(self.protocol_dir(VpnProtocol::OpenVpn))?;
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
            None => vec![VpnProtocol::OpenConnect, VpnProtocol::OpenVpn],
        };

        for proto in protocols {
            let dir = self.protocol_dir(proto);
            if !dir.is_dir() {
                continue;
            }

            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if path.extension().is_some_and(|ext| ext == "toml") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            let parsed = toml::from_str::<Profile>(&content);
                            if let Ok(profile) = parsed {
                                profiles.push(profile);
                            }
                        }
                    } else if proto == VpnProtocol::OpenVpn
                        && path.extension().is_some_and(|ext| ext == "ovpn")
                    {
                        // Check if a companion .toml exists or already loaded this profile
                        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                        let has_companion_toml = path.with_extension("toml").exists();
                        let already_loaded = profiles.iter().any(|p| p.id.0 == stem);
                        if !has_companion_toml && !already_loaded {
                            let profile = Profile::new_openvpn(
                                stem.to_string(),
                                "auto-detected",
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
        for proto in [VpnProtocol::OpenConnect, VpnProtocol::OpenVpn] {
            let dir = self.protocol_dir(proto);
            let toml_file = dir.join(format!("{}.toml", id.0));
            if toml_file.exists() {
                fs::remove_file(toml_file)?;
                removed = true;
            }
            if proto == VpnProtocol::OpenVpn {
                let ovpn_file = dir.join(format!("{}.ovpn", id.0));
                if ovpn_file.exists() {
                    fs::remove_file(ovpn_file)?;
                    removed = true;
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
}
