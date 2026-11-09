use super::config::{Profile, ProfileId, ProxyCore, ProxyRoutingMode};
use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub folder: String,
    #[serde(default)]
    pub routing_mode: ProxyRoutingMode,
    #[serde(default)]
    pub core_pref: ProxyCore,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced: Option<String>,
}

impl Subscription {
    pub fn new(name: impl Into<String>, url: impl Into<String>, folder: impl Into<String>) -> Self {
        let name_str = name.into();
        let slug = name_str
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        let id = if slug.is_empty() {
            format!(
                "sub-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            )
        } else {
            slug
        };
        Self {
            id,
            name: name_str,
            url: url.into(),
            folder: folder.into(),
            routing_mode: ProxyRoutingMode::default(),
            core_pref: ProxyCore::default(),
            last_synced: None,
        }
    }

    pub fn with_routing_mode(mut self, mode: ProxyRoutingMode) -> Self {
        self.routing_mode = mode;
        self
    }

    pub fn with_core_pref(mut self, core: ProxyCore) -> Self {
        self.core_pref = core;
        self
    }
}

pub fn current_timestamp_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (secs / 86400) as i64;
    let time_of_day = (secs % 86400) as u32;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 142401) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, m, d, hours, minutes, seconds
    )
}

fn try_decode_base64(input: &str) -> Option<String> {
    let clean = input.trim().replace(['\r', '\n', ' ', '\t'], "");
    if clean.is_empty() {
        return None;
    }

    let decode_attempts = [
        base64::engine::general_purpose::STANDARD.decode(&clean),
        base64::engine::general_purpose::URL_SAFE.decode(&clean),
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean),
    ];

    for attempt in decode_attempts {
        if let Ok(bytes) = attempt {
            if let Ok(utf8) = String::from_utf8(bytes) {
                if utf8.contains("://") {
                    return Some(utf8);
                }
            }
        }
    }
    None
}

pub fn decode_subscription_payload(raw: &str) -> Vec<String> {
    // If it decodes as base64 and contains links, use that
    if let Some(decoded) = try_decode_base64(raw) {
        return decoded
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
            .collect();
    }

    // Otherwise split raw lines
    raw.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .collect()
}

pub fn parse_subscription_profiles(
    payload: &str,
    folder: &str,
    routing_mode: ProxyRoutingMode,
    core_pref: ProxyCore,
) -> Vec<Profile> {
    let lines = decode_subscription_payload(payload);
    let mut profiles = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for (idx, line) in lines.iter().enumerate() {
        if let Ok((endpoint, remark)) = crate::domain::proxy_link::parse_share_link(line) {
            let name = match remark {
                Some(ref r) if !r.trim().is_empty() => r.trim().to_string(),
                _ => {
                    if folder.is_empty() {
                        format!("Proxy Node {}", idx + 1)
                    } else {
                        format!("{} Node {}", folder, idx + 1)
                    }
                }
            };

            let mut profile = Profile::new_v2ray(&name, &endpoint.server, None)
                .with_proxy_routing_mode(routing_mode)
                .with_proxy_core(core_pref)
                .with_proxy_endpoint(endpoint);

            if !folder.is_empty() {
                profile.group = Some(folder.to_string());
            }

            let base_id = profile.id.0.clone();
            let mut unique_id = base_id.clone();
            let mut counter = 1;
            while seen_ids.contains(&unique_id) {
                unique_id = format!("{}-{}", base_id, counter);
                counter += 1;
            }
            seen_ids.insert(unique_id.clone());
            profile.id = ProfileId(unique_id);

            profiles.push(profile);
        }
    }

    profiles
}

pub async fn fetch_subscription_feed(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let res = client
        .get(url)
        .header(reqwest::header::USER_AGENT, "v2rayN/6.23 vpn_tui/0.1")
        .send()
        .await?;

    if !res.status().is_success() {
        anyhow::bail!("Subscription server returned HTTP error: {}", res.status());
    }

    let body = res.text().await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_creation() {
        let sub = Subscription::new("My Premium Sub", "https://example.com/sub", "Premium");
        assert_eq!(sub.id, "my-premium-sub");
        assert_eq!(sub.name, "My Premium Sub");
        assert_eq!(sub.url, "https://example.com/sub");
        assert_eq!(sub.folder, "Premium");
        assert_eq!(sub.routing_mode, ProxyRoutingMode::SystemProxy);
        assert_eq!(sub.core_pref, ProxyCore::Auto);
        assert!(sub.last_synced.is_none());
    }

    #[test]
    fn test_decode_plaintext_feed() {
        let payload = r#"
# Comment line
vless://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443?encryption=none&security=tls#Node1

trojan://mysecret@5.6.7.8:443#Node2
"#;
        let lines = decode_subscription_payload(payload);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("vless://"));
        assert!(lines[1].starts_with("trojan://"));
    }

    #[test]
    fn test_decode_base64_feed() {
        let raw = "vless://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443?encryption=none#Server1\ntrojan://pass@2.3.4.5:443#Server2\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);

        let lines = decode_subscription_payload(&encoded);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("vless://"));
        assert!(lines[1].starts_with("trojan://"));
    }

    #[test]
    fn test_decode_base64_url_safe_no_pad() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@9.9.9.9:8388#SSNode\n";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

        let lines = decode_subscription_payload(&encoded);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("ss://"));
    }

    #[test]
    fn test_parse_subscription_profiles_all_types() {
        let vmess_json = r#"{"v":"2","ps":"VMessNode","add":"1.1.1.1","port":"443","id":"a0b1c2d3-e4f5-a6b7-c8d9-e0f1a2b3c4d5","aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","path":"/vmess","tls":"tls"}"#;
        let vmess_link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(vmess_json)
        );
        let vless_link = "vless://a0b1c2d3-e4f5-a6b7-c8d9-e0f1a2b3c4d5@2.2.2.2:443?encryption=none&security=reality&sni=test.com#VLESSNode";
        let trojan_link = "trojan://password123@3.3.3.3:443#TrojanNode";
        let ss_link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@4.4.4.4:8388#SSNode";

        let full_text = format!(
            "{}\n{}\n{}\n{}\ninvalid_garbage_line\n",
            vmess_link, vless_link, trojan_link, ss_link
        );

        let profiles = parse_subscription_profiles(
            &full_text,
            "MyFolder",
            ProxyRoutingMode::Tun,
            ProxyCore::SingBox,
        );

        assert_eq!(profiles.len(), 4);
        assert_eq!(profiles[0].group, Some("MyFolder".to_string()));
        assert_eq!(profiles[0].proxy_routing_mode, ProxyRoutingMode::Tun);
        assert_eq!(profiles[0].proxy_core, ProxyCore::SingBox);

        assert_eq!(profiles[0].name, "VMessNode");
        assert_eq!(profiles[1].name, "VLESSNode");
        assert_eq!(profiles[2].name, "TrojanNode");
        assert_eq!(profiles[3].name, "SSNode");
    }

    #[test]
    fn test_unique_profile_ids_on_duplicate_names() {
        let link1 = "trojan://pass@1.1.1.1:443#DuplicateName";
        let link2 = "trojan://pass@2.2.2.2:443#DuplicateName";
        let payload = format!("{}\n{}", link1, link2);

        let profiles = parse_subscription_profiles(
            &payload,
            "DupFolder",
            ProxyRoutingMode::SystemProxy,
            ProxyCore::Auto,
        );

        assert_eq!(profiles.len(), 2);
        assert_ne!(profiles[0].id, profiles[1].id);
        assert_eq!(profiles[0].id.0, "duplicatename");
        assert_eq!(profiles[1].id.0, "duplicatename-1");
    }

    #[test]
    fn test_current_timestamp_format() {
        let ts = current_timestamp_string();
        assert!(ts.contains("UTC"));
        assert_eq!(ts.len(), 23); // "YYYY-MM-DD HH:MM:SS UTC"
    }
}
