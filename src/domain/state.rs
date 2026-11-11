use super::config::{Profile, ProfileId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertWarningState {
    pub profile_id: ProfileId,
    pub endpoint: String,
    pub subject: Option<String>,
    pub pin: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    PromptingSudo,
    Authenticating,
    Connecting {
        started_at_secs: u64,
    },
    Connected {
        interface: String,
        assigned_ip: Option<String>,
        connected_at_secs: u64,
    },
    Disconnecting,
    Failed {
        error: String,
    },
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn can_connect(&self) -> bool {
        matches!(
            self,
            ConnectionState::Disconnected | ConnectionState::Failed { .. }
        )
    }

    pub fn can_disconnect(&self) -> bool {
        matches!(
            self,
            ConnectionState::Connecting { .. } | ConnectionState::Connected { .. }
        )
    }

    pub fn status_label(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "DISCONNECTED",
            ConnectionState::PromptingSudo => "AUTHENTICATING (SUDO)",
            ConnectionState::Authenticating => "AUTHENTICATING",
            ConnectionState::Connecting { .. } => "CONNECTING...",
            ConnectionState::Connected { .. } => "CONNECTED",
            ConnectionState::Disconnecting => "DISCONNECTING...",
            ConnectionState::Failed { .. } => "FAILED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LatencyState {
    #[default]
    Unknown,
    Pinging,
    Measured(u64), // milliseconds
    Timeout,
    Error(String),
}

impl LatencyState {
    pub fn display_badge(&self) -> String {
        match self {
            LatencyState::Unknown => "-- ms".to_string(),
            LatencyState::Pinging => "...".to_string(),
            LatencyState::Measured(ms) => format!("{}ms", ms),
            LatencyState::Timeout => "Timeout".to_string(),
            LatencyState::Error(_) => "Error".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogEvent {
    Stdout(String),
    Stderr(String),
    StatusChange(String),
    TunnelUp {
        interface: String,
        ip: Option<String>,
    },
    ProcessExited(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    VpnLog(LogEvent),
    PingResult {
        profile_id: ProfileId,
        latency: LatencyState,
    },
    SyncProgress(String),
    BioVpnSyncCompleted {
        profiles: Vec<Profile>,
        folders: Vec<String>,
        summary_log: String,
    },
    BioVpnSyncFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_transitions_and_predicates() {
        let state = ConnectionState::default();
        assert_eq!(state, ConnectionState::Disconnected);
        assert!(state.can_connect());
        assert!(!state.can_disconnect());
        assert!(!state.is_connected());

        let connecting = ConnectionState::Connecting {
            started_at_secs: 100,
        };
        assert!(!connecting.can_connect());
        assert!(connecting.can_disconnect());
        assert_eq!(connecting.status_label(), "CONNECTING...");

        let connected = ConnectionState::Connected {
            interface: "tun0".into(),
            assigned_ip: Some("10.8.0.2".into()),
            connected_at_secs: 110,
        };
        assert!(connected.is_connected());
        assert!(connected.can_disconnect());
        assert!(!connected.can_connect());
        assert_eq!(connected.status_label(), "CONNECTED");

        let failed = ConnectionState::Failed {
            error: "Auth failed".into(),
        };
        assert!(failed.can_connect());
        assert!(!failed.is_connected());
    }

    #[test]
    fn test_latency_state_display() {
        assert_eq!(LatencyState::Unknown.display_badge(), "-- ms");
        assert_eq!(LatencyState::Pinging.display_badge(), "...");
        assert_eq!(LatencyState::Measured(42).display_badge(), "42ms");
        assert_eq!(LatencyState::Timeout.display_badge(), "Timeout");
        assert_eq!(
            LatencyState::Error("refused".into()).display_badge(),
            "Error"
        );
    }
}
