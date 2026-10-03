use crate::domain::state::LatencyState;
use std::collections::HashMap;
use std::time::Duration;

pub trait Pinger: Send + Sync {
    fn ping(
        &self,
        endpoint: &str,
        timeout: Duration,
    ) -> impl std::future::Future<Output = LatencyState> + Send;
}

#[derive(Debug, Clone)]
pub struct MockPinger {
    pub responses: HashMap<String, LatencyState>,
    pub default_latency: LatencyState,
}

impl MockPinger {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            default_latency: LatencyState::Measured(25),
        }
    }

    pub fn with_response(mut self, endpoint: impl Into<String>, latency: LatencyState) -> Self {
        self.responses.insert(endpoint.into(), latency);
        self
    }
}

impl Default for MockPinger {
    fn default() -> Self {
        Self::new()
    }
}

impl Pinger for MockPinger {
    async fn ping(&self, endpoint: &str, _timeout: Duration) -> LatencyState {
        if let Some(res) = self.responses.get(endpoint) {
            res.clone()
        } else {
            self.default_latency.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_pinger_responses() {
        let pinger = MockPinger::new()
            .with_response("fast.server.com:443", LatencyState::Measured(12))
            .with_response("dead.server.com:443", LatencyState::Timeout);

        assert_eq!(
            pinger
                .ping("fast.server.com:443", Duration::from_secs(1))
                .await,
            LatencyState::Measured(12)
        );
        assert_eq!(
            pinger
                .ping("dead.server.com:443", Duration::from_secs(1))
                .await,
            LatencyState::Timeout
        );
        assert_eq!(
            pinger
                .ping("other.server.com:443", Duration::from_secs(1))
                .await,
            LatencyState::Measured(25)
        );
    }
}
