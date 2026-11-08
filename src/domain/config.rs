use super::account::AccountId;
use super::state::LatencyState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnProtocol {
    OpenConnect,
    OpenVpn,
}

impl VpnProtocol {
    pub fn dir_name(&self) -> &'static str {
        match self {
            VpnProtocol::OpenConnect => "openconnect",
            VpnProtocol::OpenVpn => "openvpn",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            VpnProtocol::OpenConnect => "OpenConnect",
            VpnProtocol::OpenVpn => "OpenVPN",
        }
    }
}

impl std::fmt::Display for VpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(pub String);

impl ProfileId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SslPolicy {
    #[default]
    Prompt,
    Strict,
    Insecure,
}

impl SslPolicy {
    pub fn display_name(&self) -> &'static str {
        match self {
            SslPolicy::Prompt => "Prompt on Mismatch",
            SslPolicy::Strict => "Strict CA Only",
            SslPolicy::Insecure => "Allow Insecure",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            SslPolicy::Prompt => SslPolicy::Strict,
            SslPolicy::Strict => SslPolicy::Insecure,
            SslPolicy::Insecure => SslPolicy::Prompt,
        }
    }
}

impl std::fmt::Display for SslPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: ProfileId,
    pub name: String,
    pub protocol: VpnProtocol,
    pub endpoint: String,
    pub account_id: Option<AccountId>,
    #[serde(default)]
    pub flags: Vec<String>,
    pub ovpn_file: Option<PathBuf>,
    pub authgroup: Option<String>,
    pub openconnect_protocol: Option<String>,
    #[serde(default)]
    pub ssl_policy: SslPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip)]
    pub latency: LatencyState,
}

impl Profile {
    pub fn new_openconnect(name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        let name_str = name.into();
        let slug = name_str
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        Self {
            id: ProfileId(slug),
            name: name_str,
            protocol: VpnProtocol::OpenConnect,
            endpoint: endpoint.into(),
            account_id: None,
            flags: Vec::new(),
            ovpn_file: None,
            authgroup: None,
            openconnect_protocol: Some("anyconnect".into()),
            ssl_policy: SslPolicy::default(),
            group: None,
            latency: LatencyState::Unknown,
        }
    }

    pub fn new_openvpn(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        ovpn_file: Option<PathBuf>,
    ) -> Self {
        let name_str = name.into();
        let slug = name_str
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        Self {
            id: ProfileId(slug),
            name: name_str,
            protocol: VpnProtocol::OpenVpn,
            endpoint: endpoint.into(),
            account_id: None,
            flags: Vec::new(),
            ovpn_file,
            authgroup: None,
            openconnect_protocol: None,
            ssl_policy: SslPolicy::default(),
            group: None,
            latency: LatencyState::Unknown,
        }
    }

    pub fn with_account(mut self, account_id: AccountId) -> Self {
        self.account_id = Some(account_id);
        self
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    pub fn with_flag(mut self, flag: impl Into<String>) -> Self {
        self.flags.push(flag.into());
        self
    }

    pub fn with_ssl_policy(mut self, policy: SslPolicy) -> Self {
        self.ssl_policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_protocol_attributes() {
        assert_eq!(VpnProtocol::OpenConnect.dir_name(), "openconnect");
        assert_eq!(VpnProtocol::OpenVpn.dir_name(), "openvpn");
        assert_eq!(VpnProtocol::OpenConnect.to_string(), "OpenConnect");
        assert_eq!(VpnProtocol::OpenVpn.to_string(), "OpenVPN");
    }

    #[test]
    fn test_openconnect_profile_creation() {
        let profile = Profile::new_openconnect("Office Gateway", "vpn.example.com:443")
            .with_account(AccountId("work-acc".into()))
            .with_flag("--no-dtls");

        assert_eq!(profile.id.0, "office-gateway");
        assert_eq!(profile.protocol, VpnProtocol::OpenConnect);
        assert_eq!(profile.endpoint, "vpn.example.com:443");
        assert_eq!(profile.account_id, Some(AccountId("work-acc".into())));
        assert_eq!(profile.flags, vec!["--no-dtls"]);
        assert_eq!(profile.openconnect_protocol.as_deref(), Some("anyconnect"));
    }

    #[test]
    fn test_openvpn_profile_creation() {
        let path = PathBuf::from("/etc/openvpn/client.ovpn");
        let profile = Profile::new_openvpn("Home VPN", "1.2.3.4:1194", Some(path.clone()));

        assert_eq!(profile.id.0, "home-vpn");
        assert_eq!(profile.protocol, VpnProtocol::OpenVpn);
        assert_eq!(profile.ovpn_file, Some(path));
    }

    #[test]
    fn test_ssl_policy_attributes_and_cycling() {
        assert_eq!(SslPolicy::default(), SslPolicy::Prompt);
        assert_eq!(SslPolicy::Prompt.display_name(), "Prompt on Mismatch");
        assert_eq!(SslPolicy::Strict.display_name(), "Strict CA Only");
        assert_eq!(SslPolicy::Insecure.display_name(), "Allow Insecure");

        assert_eq!(SslPolicy::Prompt.next(), SslPolicy::Strict);
        assert_eq!(SslPolicy::Strict.next(), SslPolicy::Insecure);
        assert_eq!(SslPolicy::Insecure.next(), SslPolicy::Prompt);
    }

    #[test]
    fn test_profile_toml_serialization() {
        let profile = Profile::new_openconnect("DC Frankfurt", "de.vpn.net:443")
            .with_flag("--no-dtls")
            .with_flag("--servercert=pin-sha256:abc123xyz")
            .with_ssl_policy(SslPolicy::Strict);

        let toml_str = toml::to_string(&profile).expect("failed to serialize profile");
        assert!(toml_str.contains("DC Frankfurt"));
        assert!(toml_str.contains("de.vpn.net:443"));
        assert!(toml_str.contains("ssl_policy = \"strict\""));

        let deserialized: Profile = toml::from_str(&toml_str).expect("failed to deserialize");
        assert_eq!(deserialized.name, profile.name);
        assert_eq!(deserialized.flags, profile.flags);
        assert_eq!(deserialized.ssl_policy, SslPolicy::Strict);

        // Test backward compatibility when ssl_policy is missing from TOML
        let legacy_toml = r#"
            name = "Legacy Node"
            id = "legacy-node"
            protocol = "openconnect"
            endpoint = "legacy.vpn.net:443"
            flags = []
        "#;
        let legacy_profile: Profile =
            toml::from_str(legacy_toml).expect("failed to deserialize legacy");
        assert_eq!(legacy_profile.ssl_policy, SslPolicy::Prompt);
    }

    #[test]
    fn test_profile_group_serialization_and_backward_compatibility() {
        let profile = Profile::new_openconnect("DC Frankfurt", "de.vpn.net:443")
            .with_group("BioVPN/Cisco/Europe");

        let toml_str = toml::to_string(&profile).expect("failed to serialize profile");
        assert!(toml_str.contains("group = \"BioVPN/Cisco/Europe\""));

        let deserialized: Profile = toml::from_str(&toml_str).expect("failed to deserialize");
        assert_eq!(deserialized.group.as_deref(), Some("BioVPN/Cisco/Europe"));

        // Backward compatibility: when group is absent, defaults to None
        let legacy_toml = r#"
            name = "Root Node"
            id = "root-node"
            protocol = "openconnect"
            endpoint = "root.vpn.net:443"
            flags = []
        "#;
        let legacy: Profile = toml::from_str(legacy_toml).expect("failed to deserialize legacy");
        assert_eq!(legacy.group, None);
    }
}
