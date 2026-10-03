use super::account::Credentials;
use super::config::{Profile, SslPolicy};
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

    // Profile custom / preset flags
    for flag in &profile.flags {
        let trimmed = flag.trim();
        if !trimmed.is_empty() {
            // Split if flag contains multiple space-separated arguments
            for part in trimmed.split_whitespace() {
                args.push(part.to_string());
            }
        }
    }

    // Server endpoint URL/host
    args.push(profile.endpoint.clone());

    args
}

/// Builds the command line argument list for `openvpn`.
pub fn build_openvpn_args(profile: &Profile, auth_user_pass_path: Option<&Path>) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(ovpn_path) = &profile.ovpn_file {
        args.push("--config".into());
        args.push(ovpn_path.to_string_lossy().to_string());
    }

    if let Some(auth_path) = auth_user_pass_path {
        args.push("--auth-user-pass".into());
        args.push(auth_path.to_string_lossy().to_string());
    }

    for flag in &profile.flags {
        let trimmed = flag.trim();
        if !trimmed.is_empty() {
            for part in trimmed.split_whitespace() {
                args.push(part.to_string());
            }
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
    fn test_build_openconnect_args_basic() {
        let profile = Profile::new_openconnect("Work", "vpn.corp.com:443");
        let args = build_openconnect_args(&profile, None, false);

        assert_eq!(args, vec!["--protocol=anyconnect", "vpn.corp.com:443"]);
    }

    #[test]
    fn test_build_openconnect_args_with_creds_and_flags() {
        let mut profile = Profile::new_openconnect("Work Pulse", "gateway.corp.com");
        profile.openconnect_protocol = Some("pulse".into());
        profile.flags = vec!["--no-dtls".into(), "--servercert=pin-sha256:abcd".into()];

        let creds = Credentials {
            username: Some("bob".into()),
            password: Some("secret".into()),
            auth_group: Some("Engineers".into()),
            cert_path: Some("/home/bob/.cert.pem".into()),
            token: None,
        };

        let args = build_openconnect_args(&profile, Some(&creds), true);

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
    fn test_build_openvpn_args_with_ovpn_file() {
        let profile = Profile::new_openvpn(
            "Client VPN",
            "1.2.3.4:1194",
            Some(PathBuf::from("/etc/openvpn/client.ovpn")),
        )
        .with_flag("--dev tun0");

        let auth_path = PathBuf::from("/tmp/auth.txt");
        let args = build_openvpn_args(&profile, Some(&auth_path));

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
    fn test_build_openconnect_args_insecure_policy() {
        let profile = Profile::new_openconnect("Insecure Gateway", "vpn.corp.com:443")
            .with_ssl_policy(SslPolicy::Insecure);
        let args = build_openconnect_args(&profile, None, false);

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
            .with_ssl_policy(SslPolicy::Insecure)
            .with_flag("--no-cert-check");
        let args = build_openconnect_args(&profile, None, false);

        let count = args.iter().filter(|&a| a == "--no-cert-check").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_build_openvpn_args_without_ovpn_file() {
        let profile = Profile::new_openvpn("Raw Remote", "10.0.0.1:443", None);
        let args = build_openvpn_args(&profile, None);

        assert_eq!(args, vec!["--remote", "10.0.0.1", "443"]);
    }
}
