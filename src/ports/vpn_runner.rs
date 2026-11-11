use crate::domain::account::Credentials;
use crate::domain::config::Profile;
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertProbeResult {
    Trusted,
    Warning {
        endpoint: String,
        subject: Option<String>,
        pin: String,
        reason: String,
    },
    Failed(String),
}

pub use crate::domain::state::LogEvent;

pub trait VpnRunner: Send + Sync {
    fn connect(
        &self,
        profile: &Profile,
        creds: Option<&Credentials>,
        sudo_password: Option<&str>,
        event_tx: mpsc::UnboundedSender<LogEvent>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn disconnect(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    fn check_sudo_cached(&self) -> impl std::future::Future<Output = bool> + Send;

    fn verify_sudo_password(
        &self,
        password: &str,
    ) -> impl std::future::Future<Output = bool> + Send;

    fn probe_endpoint_cert(
        &self,
        profile: &Profile,
    ) -> impl std::future::Future<Output = CertProbeResult> + Send;

    fn set_defaults(&self, _defaults: crate::domain::config::ProtocolDefaults) {}
}

#[derive(Debug, Clone)]
pub struct MockVpnRunner {
    pub is_connected: Arc<AtomicBool>,
    pub sudo_cached: bool,
    pub valid_sudo_pass: Option<String>,
    pub mock_probe_result: Option<CertProbeResult>,
}

impl MockVpnRunner {
    pub fn new() -> Self {
        Self {
            is_connected: Arc::new(AtomicBool::new(false)),
            sudo_cached: true,
            valid_sudo_pass: Some("correct_horse".into()),
            mock_probe_result: None,
        }
    }

    pub fn with_sudo_cached(mut self, cached: bool) -> Self {
        self.sudo_cached = cached;
        self
    }

    pub fn with_probe_result(mut self, res: CertProbeResult) -> Self {
        self.mock_probe_result = Some(res);
        self
    }
}

impl Default for MockVpnRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnRunner for MockVpnRunner {
    async fn connect(
        &self,
        profile: &Profile,
        _creds: Option<&Credentials>,
        _sudo_password: Option<&str>,
        event_tx: mpsc::UnboundedSender<LogEvent>,
    ) -> Result<()> {
        self.is_connected.store(true, Ordering::SeqCst);
        let _ = event_tx.send(LogEvent::Stdout(format!(
            "Connecting to {}...",
            profile.endpoint
        )));
        let _ = event_tx.send(LogEvent::TunnelUp {
            interface: "tun0".into(),
            ip: Some("10.8.0.42".into()),
        });
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        self.is_connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn check_sudo_cached(&self) -> bool {
        self.sudo_cached
    }

    async fn verify_sudo_password(&self, password: &str) -> bool {
        self.valid_sudo_pass.as_deref() == Some(password)
    }

    async fn probe_endpoint_cert(&self, _profile: &Profile) -> CertProbeResult {
        self.mock_probe_result
            .clone()
            .unwrap_or(CertProbeResult::Trusted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_vpn_runner_probe() {
        let runner = MockVpnRunner::new();
        let profile = Profile::new_openconnect("Test", "vpn.mock:443");
        assert_eq!(
            runner.probe_endpoint_cert(&profile).await,
            CertProbeResult::Trusted
        );

        let warning = CertProbeResult::Warning {
            endpoint: "vpn.mock:443".into(),
            subject: Some("vpn.mock".into()),
            pin: "pin-sha256:abc123pin".into(),
            reason: "mismatched hostname".into(),
        };
        let runner = runner.with_probe_result(warning.clone());
        assert_eq!(runner.probe_endpoint_cert(&profile).await, warning);
    }

    #[tokio::test]
    async fn test_mock_vpn_runner_connect_disconnect() {
        let runner = MockVpnRunner::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let profile = Profile::new_openconnect("Test Gateway", "vpn.mock:443");
        runner.connect(&profile, None, None, tx).await.unwrap();

        assert!(runner.is_connected.load(Ordering::SeqCst));

        let evt1 = rx.recv().await.unwrap();
        assert_eq!(
            evt1,
            LogEvent::Stdout("Connecting to vpn.mock:443...".into())
        );

        let evt2 = rx.recv().await.unwrap();
        assert_eq!(
            evt2,
            LogEvent::TunnelUp {
                interface: "tun0".into(),
                ip: Some("10.8.0.42".into())
            }
        );

        runner.disconnect().await.unwrap();
        assert!(!runner.is_connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_mock_vpn_runner_sudo_checks() {
        let runner = MockVpnRunner::new().with_sudo_cached(false);
        assert!(!runner.check_sudo_cached().await);
        assert!(runner.verify_sudo_password("correct_horse").await);
        assert!(!runner.verify_sudo_password("wrong_password").await);
    }
}
