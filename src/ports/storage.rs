use crate::domain::account::{Account, AccountId};
use crate::domain::config::{Profile, ProfileId, VpnProtocol};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub trait ConfigStorage: Send + Sync {
    fn load_accounts(&self) -> Result<Vec<Account>>;
    fn save_account(&mut self, account: &Account) -> Result<()>;
    fn delete_account(&mut self, id: &AccountId) -> Result<bool>;

    fn load_profiles(&self, protocol: Option<VpnProtocol>) -> Result<Vec<Profile>>;
    fn save_profile(&mut self, profile: &Profile) -> Result<()>;
    fn delete_profile(&mut self, id: &ProfileId) -> Result<bool>;

    fn import_ovpn(&mut self, src_path: &Path, name: &str) -> Result<Profile>;
    fn get_config_root(&self) -> PathBuf;
}

/// In-memory mock storage for unit testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStorage {
    pub root: PathBuf,
    pub accounts: HashMap<AccountId, Account>,
    pub profiles: HashMap<ProfileId, Profile>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/mock/config"),
            accounts: HashMap::new(),
            profiles: HashMap::new(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
