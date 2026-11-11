use super::account::AccountId;
use super::state::LatencyState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnProtocol {
    OpenConnect,
    OpenVpn,
    V2Ray,
}

impl VpnProtocol {
    pub fn dir_name(&self) -> &'static str {
        match self {
            VpnProtocol::OpenConnect => "openconnect",
            VpnProtocol::OpenVpn => "openvpn",
            VpnProtocol::V2Ray => "v2ray",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            VpnProtocol::OpenConnect => "OpenConnect",
            VpnProtocol::OpenVpn => "OpenVPN",
            VpnProtocol::V2Ray => "V2Ray",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyRoutingMode {
    #[default]
    SystemProxy,
    Tun,
}

impl ProxyRoutingMode {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProxyRoutingMode::SystemProxy => "System Proxy",
            ProxyRoutingMode::Tun => "TUN (Full VPN)",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ProxyRoutingMode::SystemProxy => ProxyRoutingMode::Tun,
            ProxyRoutingMode::Tun => ProxyRoutingMode::SystemProxy,
        }
    }
}

impl std::fmt::Display for ProxyRoutingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyCore {
    #[default]
    Auto,
    SingBox,
    Xray,
    V2Ray,
}

impl ProxyCore {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProxyCore::Auto => "Auto-detect",
            ProxyCore::SingBox => "sing-box",
            ProxyCore::Xray => "xray",
            ProxyCore::V2Ray => "v2ray",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ProxyCore::Auto => ProxyCore::SingBox,
            ProxyCore::SingBox => ProxyCore::Xray,
            ProxyCore::Xray => ProxyCore::V2Ray,
            ProxyCore::V2Ray => ProxyCore::Auto,
        }
    }
}

impl std::fmt::Display for ProxyCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    CustomJson,
}

impl ProxyType {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProxyType::Vmess => "VMess",
            ProxyType::Vless => "VLESS",
            ProxyType::Trojan => "Trojan",
            ProxyType::Shadowsocks => "Shadowsocks",
            ProxyType::CustomJson => "Custom JSON",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProxyEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_type: Option<ProxyType>,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid_or_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolDefaults {
    #[serde(default = "default_openconnect_flags")]
    pub openconnect_flags: Vec<String>,
    #[serde(default = "default_openvpn_flags")]
    pub openvpn_flags: Vec<String>,
}

pub fn default_openconnect_flags() -> Vec<String> {
    vec![
        "--protocol=anyconnect".to_string(),
        "--no-dtls".to_string(),
        "--pfs".to_string(),
    ]
}

pub fn default_openvpn_flags() -> Vec<String> {
    vec![
        "--dev tun".to_string(),
        "--redirect-gateway def1".to_string(),
    ]
}

impl Default for ProtocolDefaults {
    fn default() -> Self {
        Self {
            openconnect_flags: default_openconnect_flags(),
            openvpn_flags: default_openvpn_flags(),
        }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_config_file: Option<PathBuf>,
    #[serde(default)]
    pub proxy_routing_mode: ProxyRoutingMode,
    #[serde(default)]
    pub proxy_core: ProxyCore,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_endpoint: Option<ProxyEndpoint>,
    #[serde(default)]
    pub inherit_defaults: bool,
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
            proxy_config_file: None,
            proxy_routing_mode: ProxyRoutingMode::default(),
            proxy_core: ProxyCore::default(),
            proxy_endpoint: None,
            inherit_defaults: true,
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
            proxy_config_file: None,
            proxy_routing_mode: ProxyRoutingMode::default(),
            proxy_core: ProxyCore::default(),
            proxy_endpoint: None,
            inherit_defaults: true,
        }
    }

    pub fn new_v2ray(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        proxy_config_file: Option<PathBuf>,
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
            protocol: VpnProtocol::V2Ray,
            endpoint: endpoint.into(),
            account_id: None,
            flags: Vec::new(),
            ovpn_file: None,
            authgroup: None,
            openconnect_protocol: None,
            ssl_policy: SslPolicy::default(),
            group: None,
            latency: LatencyState::Unknown,
            proxy_config_file,
            proxy_routing_mode: ProxyRoutingMode::default(),
            proxy_core: ProxyCore::default(),
            proxy_endpoint: None,
            inherit_defaults: false,
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

    pub fn with_proxy_routing_mode(mut self, mode: ProxyRoutingMode) -> Self {
        self.proxy_routing_mode = mode;
        self
    }

    pub fn with_proxy_core(mut self, core: ProxyCore) -> Self {
        self.proxy_core = core;
        self
    }

    pub fn with_proxy_endpoint(mut self, endpoint: ProxyEndpoint) -> Self {
        self.proxy_endpoint = Some(endpoint);
        self
    }

    pub fn with_inherit_defaults(mut self, inherit: bool) -> Self {
        self.inherit_defaults = inherit;
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

    #[test]
    fn test_v2ray_protocol_and_proxy_models() {
        assert_eq!(VpnProtocol::V2Ray.dir_name(), "v2ray");
        assert_eq!(VpnProtocol::V2Ray.to_string(), "V2Ray");

        assert_eq!(ProxyRoutingMode::default(), ProxyRoutingMode::SystemProxy);
        assert_eq!(ProxyRoutingMode::SystemProxy.next(), ProxyRoutingMode::Tun);
        assert_eq!(ProxyRoutingMode::Tun.next(), ProxyRoutingMode::SystemProxy);

        assert_eq!(ProxyCore::default(), ProxyCore::Auto);
        assert_eq!(ProxyCore::Auto.next(), ProxyCore::SingBox);
        assert_eq!(ProxyCore::SingBox.next(), ProxyCore::Xray);
        assert_eq!(ProxyCore::Xray.next(), ProxyCore::V2Ray);
        assert_eq!(ProxyCore::V2Ray.next(), ProxyCore::Auto);

        let endpoint = ProxyEndpoint {
            protocol_type: Some(ProxyType::Vmess),
            server: "proxy.example.com".into(),
            port: 443,
            uuid_or_password: Some("12345678-1234-1234-1234-123456789abc".into()),
            network: Some("ws".into()),
            security: Some("tls".into()),
            sni: Some("proxy.example.com".into()),
            path: Some("/ws".into()),
            ..Default::default()
        };

        let profile = Profile::new_v2ray("Tokyo Node", "proxy.example.com:443", None)
            .with_proxy_routing_mode(ProxyRoutingMode::Tun)
            .with_proxy_core(ProxyCore::SingBox)
            .with_proxy_endpoint(endpoint.clone());

        assert_eq!(profile.id.0, "tokyo-node");
        assert_eq!(profile.protocol, VpnProtocol::V2Ray);
        assert_eq!(profile.proxy_routing_mode, ProxyRoutingMode::Tun);
        assert_eq!(profile.proxy_core, ProxyCore::SingBox);
        assert_eq!(profile.proxy_endpoint, Some(endpoint));

        let toml_str = toml::to_string(&profile).expect("serialize v2ray profile");
        let deserialized: Profile = toml::from_str(&toml_str).expect("deserialize v2ray profile");
        assert_eq!(deserialized.name, "Tokyo Node");
        assert_eq!(deserialized.protocol, VpnProtocol::V2Ray);
        assert_eq!(deserialized.proxy_routing_mode, ProxyRoutingMode::Tun);
        assert_eq!(deserialized.proxy_core, ProxyCore::SingBox);
    }

    #[test]
    fn test_protocol_defaults_values_and_serialization() {
        let defaults = ProtocolDefaults::default();
        assert_eq!(
            defaults.openconnect_flags,
            vec!["--protocol=anyconnect", "--no-dtls", "--pfs"]
        );
        assert_eq!(
            defaults.openvpn_flags,
            vec!["--dev tun", "--redirect-gateway def1"]
        );

        let toml_str = toml::to_string(&defaults).expect("serialize protocol defaults");
        assert!(toml_str.contains("openconnect_flags"));
        assert!(toml_str.contains("openvpn_flags"));
        assert!(toml_str.contains("--pfs"));

        let deserialized: ProtocolDefaults =
            toml::from_str(&toml_str).expect("deserialize protocol defaults");
        assert_eq!(deserialized, defaults);

        // Missing fields in TOML should use defaults
        let empty_toml = "";
        let fallback: ProtocolDefaults =
            toml::from_str(empty_toml).expect("deserialize empty toml for defaults");
        assert_eq!(fallback, defaults);
    }

    #[test]
    fn test_profile_inherit_defaults_backward_compatibility() {
        // Newly instantiated profiles default to inherit_defaults = true for OpenConnect and OpenVPN
        let oc = Profile::new_openconnect("Test OC", "vpn.example.com:443");
        assert!(oc.inherit_defaults);

        let ovpn = Profile::new_openvpn("Test OVPN", "vpn.example.com:1194", None);
        assert!(ovpn.inherit_defaults);

        let v2 = Profile::new_v2ray("Test V2", "vpn.example.com:443", None);
        assert!(!v2.inherit_defaults);

        // Builder method
        let oc_disabled = oc.clone().with_inherit_defaults(false);
        assert!(!oc_disabled.inherit_defaults);

        // Serialization includes inherit_defaults
        let toml_str = toml::to_string(&oc).unwrap();
        assert!(toml_str.contains("inherit_defaults = true"));
        let deserialized: Profile = toml::from_str(&toml_str).unwrap();
        assert!(deserialized.inherit_defaults);

        // Backward compatibility: legacy TOML omitting inherit_defaults deserializes as false
        let legacy_toml = r#"
            name = "Legacy Node"
            id = "legacy-node"
            protocol = "openconnect"
            endpoint = "legacy.vpn.net:443"
            flags = []
        "#;
        let legacy_profile: Profile = toml::from_str(legacy_toml).unwrap();
        assert!(!legacy_profile.inherit_defaults);
    }
}
