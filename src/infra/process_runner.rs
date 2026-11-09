use crate::domain::account::Credentials;
use crate::domain::config::{Profile, ProxyCore, ProxyRoutingMode, SslPolicy, VpnProtocol};
use crate::domain::flags::{build_openconnect_args, build_openvpn_args};
use crate::ports::vpn_runner::{CertProbeResult, LogEvent, VpnRunner};
use anyhow::{Context, Result};
use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub fn find_binary_in_path(name: &str) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let bin_path = dir.join(name);
            if bin_path.is_file() {
                return true;
            }
            #[cfg(windows)]
            {
                let exe_path = dir.join(format!("{}.exe", name));
                if exe_path.is_file() {
                    return true;
                }
            }
        }
    }
    false
}

pub fn resolve_proxy_binary(
    preference: ProxyCore,
    mode: ProxyRoutingMode,
) -> Result<(&'static str, ProxyCore)> {
    match preference {
        ProxyCore::SingBox => {
            if find_binary_in_path("sing-box") {
                Ok(("sing-box", ProxyCore::SingBox))
            } else {
                anyhow::bail!("sing-box binary not found in PATH");
            }
        }
        ProxyCore::Xray => {
            if find_binary_in_path("xray") {
                Ok(("xray", ProxyCore::Xray))
            } else {
                anyhow::bail!("xray binary not found in PATH");
            }
        }
        ProxyCore::V2Ray => {
            if find_binary_in_path("v2ray") {
                Ok(("v2ray", ProxyCore::V2Ray))
            } else {
                anyhow::bail!("v2ray binary not found in PATH");
            }
        }
        ProxyCore::Auto => {
            if mode == ProxyRoutingMode::Tun {
                if find_binary_in_path("sing-box") {
                    return Ok(("sing-box", ProxyCore::SingBox));
                }
                if find_binary_in_path("xray") {
                    return Ok(("xray", ProxyCore::Xray));
                }
                if find_binary_in_path("v2ray") {
                    return Ok(("v2ray", ProxyCore::V2Ray));
                }
            } else {
                if find_binary_in_path("sing-box") {
                    return Ok(("sing-box", ProxyCore::SingBox));
                }
                if find_binary_in_path("xray") {
                    return Ok(("xray", ProxyCore::Xray));
                }
                if find_binary_in_path("v2ray") {
                    return Ok(("v2ray", ProxyCore::V2Ray));
                }
            }
            anyhow::bail!(
                "No compatible proxy core found in PATH. Please install sing-box, xray, or v2ray."
            );
        }
    }
}

pub fn set_desktop_proxy(http_port: u16, socks_port: u16) -> Result<()> {
    if find_binary_in_path("gsettings") {
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.http", "host", "127.0.0.1"])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.http", "port", &http_port.to_string()])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.https", "host", "127.0.0.1"])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.https", "port", &http_port.to_string()])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])
            .status();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", &socks_port.to_string()])
            .status();
    }

    let env_file_path = std::env::temp_dir().join("vpn_tui_proxy.env");
    let env_content = format!(
        "export http_proxy=\"http://127.0.0.1:{}\"\nexport https_proxy=\"http://127.0.0.1:{}\"\nexport all_proxy=\"socks5://127.0.0.1:{}\"\n",
        http_port, http_port, socks_port
    );
    let _ = std::fs::write(env_file_path, env_content);
    Ok(())
}

pub fn clear_desktop_proxy() -> Result<()> {
    if find_binary_in_path("gsettings") {
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .status();
    }
    let env_file_path = std::env::temp_dir().join("vpn_tui_proxy.env");
    if env_file_path.exists() {
        let _ = std::fs::remove_file(env_file_path);
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct SudoProcessRunner {
    active_pid: Arc<AtomicU32>,
    is_proxy_mode: Arc<AtomicBool>,
}

impl SudoProcessRunner {
    pub fn new() -> Self {
        Self {
            active_pid: Arc::new(AtomicU32::new(0)),
            is_proxy_mode: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn parse_tunnel_from_line(line: &str) -> Option<(String, Option<String>)> {
        // OpenConnect lines: "Connected as 10.8.0.42, using SSL, with IPv6 support"
        // or "Configured as 10.8.0.42" or "tun0"
        let lower = line.to_lowercase();
        if lower.contains("tun")
            || lower.contains("connected as")
            || lower.contains("initialization sequence completed")
        {
            let iface = if lower.contains("tun1") {
                "tun1".to_string()
            } else {
                "tun0".to_string()
            };

            // Attempt to extract IP
            let ip = line.split_whitespace().find_map(|word| {
                let clean = word.trim_matches(|c: char| !c.is_numeric() && c != '.');
                let parts: Vec<&str> = clean.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    Some(clean.to_string())
                } else {
                    None
                }
            });

            return Some((iface, ip));
        }
        None
    }

    pub fn parse_cert_probe_output(output: &str, endpoint: &str) -> CertProbeResult {
        let lower = output.to_lowercase();
        let has_cert_fail = lower.contains("certificate verify failed")
            || lower.contains("failed verification")
            || lower.contains("enter 'yes' to accept")
            || lower.contains("servercert");

        if has_cert_fail {
            let pin = output
                .lines()
                .find_map(|line| {
                    if let Some(idx) = line.find("pin-sha256:") {
                        let rest = &line[idx..];
                        let token = rest.split_whitespace().next().unwrap_or(rest);
                        Some(
                            token
                                .trim_end_matches(';')
                                .trim_end_matches('.')
                                .to_string(),
                        )
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let reason = output
                .lines()
                .find_map(|line| {
                    if let Some(idx) = line.find("Reason: ") {
                        Some(line[idx + 8..].trim().to_string())
                    } else if let Some(idx) = line.find("Reason:") {
                        Some(line[idx + 7..].trim().to_string())
                    } else {
                        line.find("verify failed: ")
                            .map(|idx| line[idx + 15..].trim().to_string())
                    }
                })
                .unwrap_or_else(|| "Untrusted or mismatched certificate".to_string());

            let subject = output.lines().find_map(|line| {
                if let Some(idx) = line.find("Certificate from VPN server \"") {
                    let rest = &line[idx + 29..];
                    rest.split('"').next().map(|s| s.to_string())
                } else if let Some(idx) = line.find("CN=") {
                    let rest = &line[idx..];
                    rest.split(|c: char| c == ',' || c == '/' || c.is_whitespace())
                        .next()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            });

            if !pin.is_empty() {
                return CertProbeResult::Warning {
                    endpoint: endpoint.to_string(),
                    subject,
                    pin,
                    reason,
                };
            }
        }

        if lower.contains("failed to open")
            || lower.contains("failed to connect")
            || lower.contains("name or service not known")
            || lower.contains("unknown host")
            || lower.contains("connection refused")
        {
            let err_line = output
                .lines()
                .find(|l| {
                    let l_low = l.to_lowercase();
                    l_low.contains("failed to")
                        || l_low.contains("not known")
                        || l_low.contains("refused")
                })
                .unwrap_or("Failed to reach server")
                .trim()
                .to_string();
            return CertProbeResult::Failed(err_line);
        }

        CertProbeResult::Trusted
    }
}

impl VpnRunner for SudoProcessRunner {
    async fn check_sudo_cached(&self) -> bool {
        let output = Command::new("sudo").arg("-n").arg("-v").output().await;

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    async fn verify_sudo_password(&self, password: &str) -> bool {
        let mut child = match Command::new("sudo")
            .arg("-S")
            .arg("-v")
            .arg("-p")
            .arg("")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(format!("{}\n", password).as_bytes()).await;
        }

        match child.wait().await {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    async fn connect(
        &self,
        profile: &Profile,
        creds: Option<&Credentials>,
        sudo_password: Option<&str>,
        event_tx: mpsc::UnboundedSender<LogEvent>,
    ) -> Result<()> {
        let (use_sudo, binary, args, stdin_data) = match profile.protocol {
            VpnProtocol::OpenConnect => {
                let has_password = creds.and_then(|c| c.password.as_deref()).is_some();
                let args = build_openconnect_args(profile, creds, has_password);
                let stdin_data = creds
                    .and_then(|c| c.password.as_deref())
                    .map(|p| format!("{}\n", p));
                (true, "openconnect".to_string(), args, stdin_data)
            }
            VpnProtocol::OpenVpn => {
                // Build auth-user-pass temporary file if credentials exist
                let auth_file_path = if let Some(creds) = creds {
                    if let (Some(u), Some(p)) = (&creds.username, &creds.password) {
                        let path =
                            std::env::temp_dir().join(format!("vpn_auth_{}.tmp", profile.id.0));
                        let mut file = std::fs::File::create(&path)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
                        }
                        writeln!(file, "{}\n{}", u, p)?;
                        Some(path)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let args = build_openvpn_args(profile, auth_file_path.as_deref());
                (true, "openvpn".to_string(), args, None)
            }
            VpnProtocol::V2Ray => {
                let (bin_name, chosen_core) =
                    resolve_proxy_binary(profile.proxy_core, profile.proxy_routing_mode)?;

                let config_path_buf = if let Some(ref path) = profile.proxy_config_file {
                    path.clone()
                } else if let Some(ref endpoint) = profile.proxy_endpoint {
                    let runtime_json = crate::infra::proxy_config_gen::generate_runtime_config(
                        chosen_core,
                        endpoint,
                        profile.proxy_routing_mode,
                    )?;
                    let tmp_path =
                        std::env::temp_dir().join(format!("vpn_tui_v2ray_{}.json", profile.id.0));
                    std::fs::write(&tmp_path, runtime_json)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &tmp_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                    tmp_path
                } else {
                    anyhow::bail!(
                        "V2Ray profile has neither a config file nor an endpoint configuration"
                    );
                };

                let config_arg = config_path_buf.to_string_lossy().to_string();
                let mut proxy_args = vec!["run".to_string(), "-c".to_string(), config_arg];
                for flag in &profile.flags {
                    let trimmed = flag.trim();
                    if !trimmed.is_empty() {
                        for part in trimmed.split_whitespace() {
                            proxy_args.push(part.to_string());
                        }
                    }
                }

                let use_sudo = profile.proxy_routing_mode == ProxyRoutingMode::Tun;
                if profile.proxy_routing_mode == ProxyRoutingMode::SystemProxy {
                    let _ = set_desktop_proxy(10809, 10808);
                    self.is_proxy_mode.store(true, Ordering::SeqCst);
                    let _ = event_tx.send(LogEvent::Stdout(
                        "Local proxy listening on 127.0.0.1:10808 (SOCKS5) and 127.0.0.1:10809 (HTTP)".into(),
                    ));
                    let _ = event_tx.send(LogEvent::TunnelUp {
                        interface: "proxy".into(),
                        ip: Some("127.0.0.1".into()),
                    });
                } else {
                    self.is_proxy_mode.store(false, Ordering::SeqCst);
                }

                (use_sudo, bin_name.to_string(), proxy_args, None)
            }
        };

        if use_sudo {
            if let Some(pass) = sudo_password {
                let valid = self.verify_sudo_password(pass).await;
                if !valid {
                    anyhow::bail!("Invalid sudo password");
                }
            }
        }

        let mut cmd = if use_sudo {
            let mut c = Command::new("sudo");
            c.arg("-E").arg(&binary).args(&args);
            c
        } else {
            let mut c = Command::new(&binary);
            c.args(&args);
            c
        };
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn {}", binary))?;

        if let Some(pid) = child.id() {
            self.active_pid.store(pid, Ordering::SeqCst);
        }

        if let (Some(mut stdin), Some(data)) = (child.stdin.take(), stdin_data) {
            use tokio::io::AsyncWriteExt;
            tokio::spawn(async move {
                let _ = stdin.write_all(data.as_bytes()).await;
            });
        }

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let tx_out = event_tx.clone();
        let tx_err = event_tx.clone();

        if let Some(stdout) = stdout {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    if let Some((iface, ip)) = SudoProcessRunner::parse_tunnel_from_line(&line) {
                        let _ = tx_out.send(LogEvent::TunnelUp {
                            interface: iface,
                            ip,
                        });
                    }
                    let _ = tx_out.send(LogEvent::Stdout(line));
                }
            });
        }

        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx_err.send(LogEvent::Stderr(line));
                }
            });
        }

        let pid_holder = self.active_pid.clone();
        let proxy_mode_holder = self.is_proxy_mode.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            pid_holder.store(0, Ordering::SeqCst);
            if proxy_mode_holder.swap(false, Ordering::SeqCst) {
                let _ = clear_desktop_proxy();
            }
            let code = status.map_or(-1, |s| s.code().unwrap_or(-1));
            let _ = event_tx.send(LogEvent::ProcessExited(code));
        });

        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        let pid = self.active_pid.swap(0, Ordering::SeqCst);
        if pid > 0 {
            // Send SIGINT / SIGTERM for graceful shutdown
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGINT);
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .status();
            }
        }
        if self.is_proxy_mode.swap(false, Ordering::SeqCst) {
            let _ = clear_desktop_proxy();
        }
        Ok(())
    }

    async fn probe_endpoint_cert(&self, profile: &Profile) -> CertProbeResult {
        if profile.protocol != VpnProtocol::OpenConnect {
            return CertProbeResult::Trusted;
        }

        if profile.ssl_policy == SslPolicy::Insecure {
            return CertProbeResult::Trusted;
        }

        if profile.flags.iter().any(|f| f.contains("--no-cert-check")) {
            return CertProbeResult::Trusted;
        }

        if profile.flags.iter().any(|f| f.contains("--servercert")) {
            return CertProbeResult::Trusted;
        }

        let mut cmd = Command::new("openconnect");
        cmd.arg("--authenticate");
        let proto = profile
            .openconnect_protocol
            .as_deref()
            .unwrap_or("anyconnect");
        cmd.arg(format!("--protocol={}", proto));
        cmd.arg(&profile.endpoint);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let timeout_duration = std::time::Duration::from_secs(4);
        match tokio::time::timeout(timeout_duration, cmd.output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let combined = format!("{}\n{}", stdout, stderr);
                SudoProcessRunner::parse_cert_probe_output(&combined, &profile.endpoint)
            }
            Ok(Err(e)) => CertProbeResult::Failed(format!("Failed to execute probe: {}", e)),
            Err(_) => CertProbeResult::Failed("Certificate probe timed out".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert_probe_warning() {
        let sample = r#"
POST https://45.93.169.132/
Connected to 45.93.169.132:443
SSL negotiation with 45.93.169.132
Server certificate verify failed: certificate does not match hostname

Certificate from VPN server "45.93.169.132" failed verification.
Reason: certificate does not match hostname
To trust this server in future, perhaps add this to your command line:
    --servercert pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=
Enter 'yes' to accept, 'no' to abort; anything else to view: fgets (stdin): Permission denied
"#;
        let res = SudoProcessRunner::parse_cert_probe_output(sample, "45.93.169.132:443");
        assert_eq!(
            res,
            CertProbeResult::Warning {
                endpoint: "45.93.169.132:443".into(),
                subject: Some("45.93.169.132".into()),
                pin: "pin-sha256:Iir9uh8Bo4nogJDh6X3C3ulRIXorMbCvCAJPmkCC4os=".into(),
                reason: "certificate does not match hostname".into(),
            }
        );
    }

    #[test]
    fn test_parse_cert_probe_trusted() {
        let sample = r#"
POST https://vpn.corp.com/
Connected to 1.2.3.4:443
Connected to HTTPS on vpn.corp.com with ciphersuite TLS1.3
Please enter your username and password.
"#;
        let res = SudoProcessRunner::parse_cert_probe_output(sample, "vpn.corp.com");
        assert_eq!(res, CertProbeResult::Trusted);
    }

    #[test]
    fn test_parse_cert_probe_failed() {
        let sample = "Failed to connect to host bad.endpoint.corp: Name or service not known";
        let res = SudoProcessRunner::parse_cert_probe_output(sample, "bad.endpoint.corp");
        assert!(matches!(res, CertProbeResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_probe_endpoint_cert_skips_when_insecure_or_pinned() {
        let runner = SudoProcessRunner::new();

        // Insecure policy skips probe
        let p_insecure = Profile::new_openconnect("Test Insecure", "1.2.3.4:443")
            .with_ssl_policy(SslPolicy::Insecure);
        assert_eq!(
            runner.probe_endpoint_cert(&p_insecure).await,
            CertProbeResult::Trusted
        );

        // Pinned cert skips probe
        let p_pinned = Profile::new_openconnect("Test Pinned", "1.2.3.4:443")
            .with_flag("--servercert=pin-sha256:abc");
        assert_eq!(
            runner.probe_endpoint_cert(&p_pinned).await,
            CertProbeResult::Trusted
        );

        // OpenVPN skips probe
        let p_ovpn = Profile::new_openvpn("Test OVPN", "1.2.3.4:1194", None);
        assert_eq!(
            runner.probe_endpoint_cert(&p_ovpn).await,
            CertProbeResult::Trusted
        );
    }

    #[test]
    fn test_parse_tunnel_openconnect_log() {
        let line = "Connected as 10.8.0.42, using SSL, with IPv6 support";
        let parsed = SudoProcessRunner::parse_tunnel_from_line(line);
        assert_eq!(
            parsed,
            Some(("tun0".to_string(), Some("10.8.0.42".to_string())))
        );
    }

    #[test]
    fn test_parse_tunnel_openvpn_log() {
        let line = "Initialization Sequence Completed on tun0";
        let parsed = SudoProcessRunner::parse_tunnel_from_line(line);
        assert_eq!(parsed, Some(("tun0".to_string(), None)));
    }

    #[test]
    fn test_parse_regular_log_returns_none() {
        let line = "POST https://vpn.corp.com/auth";
        assert_eq!(SudoProcessRunner::parse_tunnel_from_line(line), None);
    }

    #[tokio::test]
    async fn test_runner_initial_pid_and_disconnect() {
        let runner = SudoProcessRunner::new();
        assert_eq!(runner.active_pid.load(Ordering::SeqCst), 0);
        assert!(runner.disconnect().await.is_ok());
    }

    #[test]
    fn test_find_binary_in_path() {
        // Standard unix binaries should exist in PATH
        assert!(find_binary_in_path("sh") || find_binary_in_path("ls"));
        assert!(!find_binary_in_path("non_existent_binary_xyz_123"));
    }

    #[test]
    fn test_desktop_proxy_env_hooks() {
        let _ = set_desktop_proxy(10809, 10808);
        let env_file = std::env::temp_dir().join("vpn_tui_proxy.env");
        assert!(env_file.exists());
        let content = std::fs::read_to_string(&env_file).unwrap();
        assert!(content.contains("http://127.0.0.1:10809"));
        assert!(content.contains("socks5://127.0.0.1:10808"));

        let _ = clear_desktop_proxy();
        assert!(!env_file.exists());
    }
}
