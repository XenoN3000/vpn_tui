use super::account::Credentials;
use super::config::{Profile, ProtocolDefaults, SslPolicy};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VpnFlags {
    pub preset_flags: Vec<String>,
    pub custom_flags: Vec<String>,
}

impl VpnFlags {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_preset(mut self, flag: impl Into<String>) -> Self {
        self.preset_flags.push(flag.into());
        self
    }

    pub fn with_custom(mut self, flag: impl Into<String>) -> Self {
        self.custom_flags.push(flag.into());
        self
    }

    pub fn all_flags(&self) -> Vec<String> {
        let mut all = self.preset_flags.clone();
        all.extend(self.custom_flags.clone());
        all
    }
}

/// Builds the command line argument list for `openconnect`.
pub fn build_openconnect_args(
    profile: &Profile,
    credentials: Option<&Credentials>,
    passwd_on_stdin: bool,
    defaults: Option<&ProtocolDefaults>,
) -> Vec<String> {
    let mut args = Vec::new();

    // Protocol: e.g. anyconnect, pulse, gp
    let proto = profile
        .openconnect_protocol
        .as_deref()
        .unwrap_or("anyconnect");
    args.push(format!("--protocol={}", proto));

    // Credentials - User
    if let Some(user) = credentials
        .and_then(|c| c.username.as_deref())
        .filter(|u| !u.is_empty())
    {
        args.push(format!("--user={}", user));
    }

    // Authgroup: profile overrides creds
    let authgroup = profile
        .authgroup
        .as_deref()
        .or_else(|| credentials.and_then(|c| c.auth_group.as_deref()));
    if let Some(group) = authgroup.filter(|g| !g.is_empty()) {
        args.push(format!("--authgroup={}", group));
    }

    // Client certificate
    if let Some(cert) = credentials
        .and_then(|c| c.cert_path.as_deref())
        .filter(|c| !c.is_empty())
    {
        args.push(format!("--certificate={}", cert));
    }

    // Token
    if let Some(token) = credentials
        .and_then(|c| c.token.as_deref())
        .filter(|t| !t.is_empty())
    {
        args.push(format!("--token-secret={}", token));
    }

    // Password on stdin
    if passwd_on_stdin {
        args.push("--passwd-on-stdin".into());
    }

    // SSL Policy: Insecure bypasses certificate verification
    if profile.ssl_policy == SslPolicy::Insecure
        && !profile.flags.iter().any(|f| f.contains("--no-cert-check"))
    {
        args.push("--no-cert-check".into());
    }

    // Merge default flags if inherit_defaults is true
    let default_flags: Vec<String> = if profile.inherit_defaults {
        defaults
            .map(|d| d.openconnect_flags.clone())
            .unwrap_or_else(crate::domain::config::default_openconnect_flags)
    } else {
        Vec::new()
    };

    let mut combined_flags = Vec::new();
    for f in &default_flags {
        for part in f.split_whitespace() {
            if !part.starts_with("--protocol=") {
                combined_flags.push(part.to_string());
            }
        }
    }
    for f in &profile.flags {
        for part in f.split_whitespace() {
            combined_flags.push(part.to_string());
        }
    }

    for flag in combined_flags {
        if (flag == "--no-dtls" || flag == "--pfs" || flag == "--no-cert-check")
            && args.iter().any(|a| a == &flag)
        {
            continue;
        }
        args.push(flag);
    }

    // Server endpoint URL/host
    args.push(profile.endpoint.clone());

    args
}

/// Builds the command line argument list for `openvpn`.
pub fn build_openvpn_args(
    profile: &Profile,
    auth_user_pass_path: Option<&Path>,
    defaults: Option<&ProtocolDefaults>,
) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(ovpn_path) = &profile.ovpn_file {
        args.push("--config".into());
        args.push(ovpn_path.to_string_lossy().to_string());
    }

    if let Some(auth_path) = auth_user_pass_path {
        args.push("--auth-user-pass".into());
        args.push(auth_path.to_string_lossy().to_string());
    }

    let default_flags: Vec<String> = if profile.inherit_defaults {
        defaults
            .map(|d| d.openvpn_flags.clone())
            .unwrap_or_else(crate::domain::config::default_openvpn_flags)
    } else {
        Vec::new()
    };

    let profile_has_dev = profile.flags.iter().any(|f| f.contains("--dev"));
    let profile_has_redirect = profile
        .flags
        .iter()
        .any(|f| f.contains("--redirect-gateway"));

    for flag in &default_flags {
        if profile_has_dev && flag.contains("--dev") {
            continue;
        }
        if profile_has_redirect && flag.contains("--redirect-gateway") {
            continue;
        }
        for part in flag.split_whitespace() {
            args.push(part.to_string());
        }
    }

    for flag in &profile.flags {
        for part in flag.split_whitespace() {
            args.push(part.to_string());
        }
    }

    // If no ovpn file is present, add remote host/port from endpoint
    if profile.ovpn_file.is_none() && !profile.endpoint.is_empty() {
        if let Some((host, port)) = profile.endpoint.split_once(':') {
            args.push("--remote".into());
            args.push(host.to_string());
            args.push(port.to_string());
        } else {
            args.push("--remote".into());
            args.push(profile.endpoint.clone());
        }
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_openconnect_args_basic_without_defaults() {
        let profile =
            Profile::new_openconnect("Work", "vpn.corp.com:443").with_inherit_defaults(false);
        let args = build_openconnect_args(&profile, None, false, None);

        assert_eq!(args, vec!["--protocol=anyconnect", "vpn.corp.com:443"]);
    }

    #[test]
    fn test_build_openconnect_args_with_inherited_defaults() {
        let profile = Profile::new_openconnect("Work", "vpn.corp.com:443");
        let args = build_openconnect_args(&profile, None, false, None);

        assert_eq!(
            args,
            vec![
                "--protocol=anyconnect",
                "--no-dtls",
                "--pfs",
                "vpn.corp.com:443"
            ]
        );
    }

    #[test]
    fn test_build_openconnect_args_with_creds_and_flags() {
        let mut profile =
            Profile::new_openconnect("Work Pulse", "gateway.corp.com").with_inherit_defaults(false);
        profile.openconnect_protocol = Some("pulse".into());
        profile.flags = vec!["--no-dtls".into(), "--servercert=pin-sha256:abcd".into()];

        let creds = Credentials {
            username: Some("bob".into()),
            password: Some("secret".into()),
            auth_group: Some("Engineers".into()),
            cert_path: Some("/home/bob/.cert.pem".into()),
            token: None,
        };

        let args = build_openconnect_args(&profile, Some(&creds), true, None);

        assert_eq!(
            args,
            vec![
                "--protocol=pulse",
                "--user=bob",
                "--authgroup=Engineers",
                "--certificate=/home/bob/.cert.pem",
                "--passwd-on-stdin",
                "--no-dtls",
                "--servercert=pin-sha256:abcd",
                "gateway.corp.com"
            ]
        );
    }

    #[test]
    fn test_build_openconnect_args_deduplicate_flags() {
        let profile = Profile::new_openconnect("Work", "vpn.corp.com:443")
            .with_flag("--no-dtls")
            .with_flag("--pfs");
        let args = build_openconnect_args(&profile, None, false, None);

        let dtls_count = args.iter().filter(|&a| a == "--no-dtls").count();
        let pfs_count = args.iter().filter(|&a| a == "--pfs").count();
        assert_eq!(dtls_count, 1);
        assert_eq!(pfs_count, 1);
    }

    #[test]
    fn test_build_openvpn_args_with_ovpn_file_without_defaults() {
        let profile = Profile::new_openvpn(
            "Client VPN",
            "1.2.3.4:1194",
            Some(PathBuf::from("/etc/openvpn/client.ovpn")),
        )
        .with_inherit_defaults(false)
        .with_flag("--dev tun0");

        let auth_path = PathBuf::from("/tmp/auth.txt");
        let args = build_openvpn_args(&profile, Some(&auth_path), None);

        assert_eq!(
            args,
            vec![
                "--config",
                "/etc/openvpn/client.ovpn",
                "--auth-user-pass",
                "/tmp/auth.txt",
                "--dev",
                "tun0"
            ]
        );
    }

    #[test]
    fn test_build_openvpn_args_with_inherited_defaults() {
        let profile = Profile::new_openvpn(
            "Client VPN",
            "1.2.3.4:1194",
            Some(PathBuf::from("/etc/openvpn/client.ovpn")),
        );

        let args = build_openvpn_args(&profile, None, None);

        assert_eq!(
            args,
            vec![
                "--config",
                "/etc/openvpn/client.ovpn",
                "--dev",
                "tun",
                "--redirect-gateway",
                "def1"
            ]
        );
    }

    #[test]
    fn test_build_openvpn_args_override_defaults() {
        let profile = Profile::new_openvpn(
            "Client VPN",
            "1.2.3.4:1194",
            Some(PathBuf::from("/etc/openvpn/client.ovpn")),
        )
        .with_flag("--dev tap");

        let args = build_openvpn_args(&profile, None, None);

        // --dev tun should be omitted in favor of profile's --dev tap
        assert!(!args.iter().any(|a| a == "tun"));
        assert_eq!(
            args,
            vec![
                "--config",
                "/etc/openvpn/client.ovpn",
                "--redirect-gateway",
                "def1",
                "--dev",
                "tap"
            ]
        );
    }

    #[test]
    fn test_build_openconnect_args_insecure_policy() {
        let profile = Profile::new_openconnect("Insecure Gateway", "vpn.corp.com:443")
            .with_inherit_defaults(false)
            .with_ssl_policy(SslPolicy::Insecure);
        let args = build_openconnect_args(&profile, None, false, None);

        assert_eq!(
            args,
            vec![
                "--protocol=anyconnect",
                "--no-cert-check",
                "vpn.corp.com:443"
            ]
        );
    }

    #[test]
    fn test_build_openconnect_args_insecure_policy_no_duplicates() {
        let profile = Profile::new_openconnect("Insecure Gateway", "vpn.corp.com:443")
            .with_inherit_defaults(false)
            .with_ssl_policy(SslPolicy::Insecure)
            .with_flag("--no-cert-check");
        let args = build_openconnect_args(&profile, None, false, None);

        let count = args.iter().filter(|&a| a == "--no-cert-check").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_build_openvpn_args_without_ovpn_file() {
        let profile =
            Profile::new_openvpn("Raw Remote", "10.0.0.1:443", None).with_inherit_defaults(false);
        let args = build_openvpn_args(&profile, None, None);

        assert_eq!(args, vec!["--remote", "10.0.0.1", "443"]);
    }
}
