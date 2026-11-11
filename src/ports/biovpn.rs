use anyhow::Result;
use std::future::Future;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedOvpnConfig {
    pub server_name: String,
    pub country_group: String,
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSyncData {
    pub zip_bytes: Vec<u8>,
    pub dashboard_html: Option<String>,
    pub individual_ovpns: Vec<DownloadedOvpnConfig>,
    pub logs: Vec<String>,
}

pub trait BioVpnClient: Send + Sync {
    /// Authenticates with the BioVPN portal and fetches the bundle along with dashboard HTML.
    fn fetch_bundle(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<PortalSyncData>> + Send;

    /// Fetches the raw bytes of the public configuration ZIP bundle directly without credentials.
    fn fetch_direct_bundle(&self) -> impl Future<Output = Result<PortalSyncData>> + Send;
}
