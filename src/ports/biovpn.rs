use anyhow::Result;
use std::future::Future;

pub trait BioVpnClient: Send + Sync {
    /// Authenticates with the BioVPN portal and fetches the raw bytes of the configuration ZIP bundle.
    fn fetch_bundle(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Fetches the raw bytes of the public configuration ZIP bundle directly without credentials.
    fn fetch_direct_bundle(
        &self,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
