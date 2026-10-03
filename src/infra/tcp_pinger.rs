use crate::domain::state::LatencyState;
use crate::ports::pinger::Pinger;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct TcpPinger {
    default_port: u16,
}

impl TcpPinger {
    pub fn new() -> Self {
        Self { default_port: 443 }
    }

    pub fn with_default_port(mut self, port: u16) -> Self {
        self.default_port = port;
        self
    }

    /// Normalizes endpoint string to include a port if omitted
    fn normalize_endpoint(&self, endpoint: &str) -> String {
        let trimmed = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');

        if trimmed.contains(':') {
            trimmed.to_string()
        } else {
            format!("{}:{}", trimmed, self.default_port)
        }
    }
}

impl Pinger for TcpPinger {
    async fn ping(&self, endpoint: &str, duration: Duration) -> LatencyState {
        let target = self.normalize_endpoint(endpoint);
        let start = Instant::now();

        match timeout(duration, TcpStream::connect(&target)).await {
            Ok(Ok(_stream)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                LatencyState::Measured(elapsed.max(1))
            }
            Ok(Err(err)) => LatencyState::Error(err.to_string()),
            Err(_) => LatencyState::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_pinger_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pinger = TcpPinger::new();
        let res = pinger
            .ping(&addr.to_string(), Duration::from_millis(500))
            .await;

        match res {
            LatencyState::Measured(ms) => {
                assert!(ms < 500);
            }
            other => panic!("Expected Measured latency, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_tcp_pinger_timeout() {
        let pinger = TcpPinger::new();
        // 192.0.2.1 is reserved TEST-NET-1 which typically drops packets
        let res = pinger
            .ping("192.0.2.1:443", Duration::from_millis(50))
            .await;
        assert_eq!(res, LatencyState::Timeout);
    }

    #[test]
    fn test_normalize_endpoint() {
        let pinger = TcpPinger::new().with_default_port(443);
        assert_eq!(
            pinger.normalize_endpoint("https://vpn.example.com"),
            "vpn.example.com:443"
        );
        assert_eq!(
            pinger.normalize_endpoint("vpn.example.com:8443"),
            "vpn.example.com:8443"
        );
    }
}
