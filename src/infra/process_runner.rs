use crate::domain::account::Credentials;
use crate::domain::config::{Profile, SslPolicy, VpnProtocol};
use crate::domain::flags::{build_openconnect_args, build_openvpn_args};
use crate::ports::vpn_runner::{CertProbeResult, LogEvent, VpnRunner};
use anyhow::{Context, Result};
use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Default)]
pub struct SudoProcessRunner {
    active_pid: Arc<AtomicU32>,
}

impl SudoProcessRunner {
    pub fn new() -> Self {
        Self {
            active_pid: Arc::new(AtomicU32::new(0)),
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
        let (binary, args, stdin_data) = match profile.protocol {
            VpnProtocol::OpenConnect => {
                let has_password = creds.and_then(|c| c.password.as_deref()).is_some();
                let args = build_openconnect_args(profile, creds, has_password);
                let stdin_data = creds
                    .and_then(|c| c.password.as_deref())
                    .map(|p| format!("{}\n", p));
                ("openconnect", args, stdin_data)
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
                ("openvpn", args, None)
            }
        };

        // If sudo password is provided, verify it first
        if let Some(pass) = sudo_password {
            let valid = self.verify_sudo_password(pass).await;
            if !valid {
                anyhow::bail!("Invalid sudo password");
            }
        }

        let mut cmd = Command::new("sudo");
        cmd.arg("-E").arg(binary).args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn sudo -E {}", binary))?;

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
        tokio::spawn(async move {
            let status = child.wait().await;
            pid_holder.store(0, Ordering::SeqCst);
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
}
