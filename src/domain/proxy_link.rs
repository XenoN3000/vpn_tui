use super::config::{ProxyEndpoint, ProxyType};
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

fn decode_base64_flexible(input: &str) -> Result<Vec<u8>> {
    let clean = input.trim().replace(['\r', '\n', ' '], "");
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(&clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&clean)
        .with_context(|| format!("Failed to base64-decode: {}", input))
}

fn url_decode(s: &str) -> String {
    let mut res = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                let hex_str = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    res.push(byte as char);
                    continue;
                }
            }
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}

#[derive(Debug, Deserialize)]
struct VmessJson {
    pub ps: Option<String>,
    pub add: Option<String>,
    #[serde(default)]
    pub port: serde_json::Value,
    pub id: Option<String>,
    #[serde(default)]
    pub aid: serde_json::Value,
    pub scy: Option<String>,
    pub net: Option<String>,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub header_type: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub tls: Option<String>,
    pub sni: Option<String>,
}

fn parse_port_value(val: &serde_json::Value) -> u16 {
    match val {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(443) as u16,
        serde_json::Value::String(s) => s.parse::<u16>().unwrap_or(443),
        _ => 443,
    }
}

fn parse_aid_value(val: &serde_json::Value) -> Option<u32> {
    match val {
        serde_json::Value::Number(n) => n.as_u64().map(|v| v as u32),
        serde_json::Value::String(s) => s.parse::<u32>().ok(),
        _ => None,
    }
}

pub fn parse_vmess(link: &str) -> Result<(ProxyEndpoint, Option<String>)> {
    let raw = link.strip_prefix("vmess://").unwrap_or(link);
    let bytes = decode_base64_flexible(raw)?;
    let json_str = String::from_utf8(bytes).context("VMess payload is not valid UTF-8")?;

    let vmess: VmessJson =
        serde_json::from_str(&json_str).context("Failed to parse VMess JSON payload")?;

    let server = vmess.add.unwrap_or_default().trim().to_string();
    if server.is_empty() {
        bail!("VMess link missing server address (add)");
    }
    let port = parse_port_value(&vmess.port);
    let name = vmess.ps.filter(|s| !s.trim().is_empty());
    let uuid = vmess.id.filter(|s| !s.trim().is_empty());
    let alter_id = parse_aid_value(&vmess.aid);
    let network = vmess.net.filter(|s| !s.trim().is_empty());

    let security = match vmess.tls.as_deref() {
        Some("tls") => Some("tls".to_string()),
        Some("reality") => Some("reality".to_string()),
        _ => None,
    };

    let sni = vmess
        .sni
        .filter(|s| !s.trim().is_empty())
        .or_else(|| vmess.host.filter(|s| !s.trim().is_empty()));

    let endpoint = ProxyEndpoint {
        protocol_type: Some(ProxyType::Vmess),
        server,
        port,
        uuid_or_password: uuid,
        alter_id,
        cipher: vmess.scy,
        network,
        security,
        sni,
        path: vmess.path.filter(|s| !s.trim().is_empty()),
        raw_link: Some(link.to_string()),
    };

    Ok((endpoint, name))
}

pub fn parse_vless(link: &str) -> Result<(ProxyEndpoint, Option<String>)> {
    let raw = link.strip_prefix("vless://").unwrap_or(link);
    parse_uri_style_proxy(raw, ProxyType::Vless, link)
}

pub fn parse_trojan(link: &str) -> Result<(ProxyEndpoint, Option<String>)> {
    let raw = link.strip_prefix("trojan://").unwrap_or(link);
    parse_uri_style_proxy(raw, ProxyType::Trojan, link)
}

fn parse_uri_style_proxy(
    raw: &str,
    proto: ProxyType,
    full_link: &str,
) -> Result<(ProxyEndpoint, Option<String>)> {
    // Format: credentials@host:port?query#name
    let (without_name, name) = match raw.split_once('#') {
        Some((w, n)) => (w, Some(url_decode(n))),
        None => (raw, None),
    };

    let (creds_and_host, query) = match without_name.split_once('?') {
        Some((ch, q)) => (ch, Some(q)),
        None => (without_name, None),
    };

    let (creds, host_port) = match creds_and_host.split_once('@') {
        Some((c, hp)) => (c, hp),
        None => bail!("Missing credentials (@) in URI"),
    };

    let (server, port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let port_num = p.parse::<u16>().context("Invalid port in URI")?;
            (h.to_string(), port_num)
        }
        None => {
            let default_port = match proto {
                ProxyType::Trojan => 443,
                _ => 443,
            };
            (host_port.to_string(), default_port)
        }
    };

    let mut network = None;
    let mut security = None;
    let mut sni = None;
    let mut path = None;

    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let decoded_v = url_decode(v);
                match k {
                    "type" | "transport" => network = Some(decoded_v),
                    "security" => security = Some(decoded_v),
                    "sni" => sni = Some(decoded_v),
                    "path" => path = Some(decoded_v),
                    "serviceName" => path = Some(decoded_v),
                    _ => {}
                }
            }
        }
    }

    let endpoint = ProxyEndpoint {
        protocol_type: Some(proto),
        server,
        port,
        uuid_or_password: Some(url_decode(creds)),
        alter_id: None,
        cipher: None,
        network,
        security,
        sni,
        path,
        raw_link: Some(full_link.to_string()),
    };

    Ok((endpoint, name))
}

pub fn parse_shadowsocks(link: &str) -> Result<(ProxyEndpoint, Option<String>)> {
    let raw = link.strip_prefix("ss://").unwrap_or(link);
    let (without_name, name) = match raw.split_once('#') {
        Some((w, n)) => (w, Some(url_decode(n))),
        None => (raw, None),
    };

    // Case 1: SIP002 format: BASE64(method:password)@host:port
    if let Some((encoded_userinfo, host_port)) = without_name.split_once('@') {
        let (server, port) = match host_port.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(8388)),
            None => (host_port.to_string(), 8388),
        };

        let decoded_userinfo = match decode_base64_flexible(encoded_userinfo) {
            Ok(b) => String::from_utf8(b).unwrap_or_default(),
            Err(_) => encoded_userinfo.to_string(),
        };

        let (cipher, password) = match decoded_userinfo.split_once(':') {
            Some((c, p)) => (Some(c.to_string()), Some(p.to_string())),
            None => (None, Some(decoded_userinfo)),
        };

        let endpoint = ProxyEndpoint {
            protocol_type: Some(ProxyType::Shadowsocks),
            server,
            port,
            uuid_or_password: password,
            alter_id: None,
            cipher,
            network: Some("tcp".to_string()),
            security: None,
            sni: None,
            path: None,
            raw_link: Some(link.to_string()),
        };

        return Ok((endpoint, name));
    }

    // Case 2: Legacy format: BASE64(method:password@host:port)
    let decoded_all = decode_base64_flexible(without_name)?;
    let all_str = String::from_utf8(decoded_all).context("Invalid Shadowsocks base64 payload")?;

    if let Some((userinfo, host_port)) = all_str.split_once('@') {
        let (server, port) = match host_port.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(8388)),
            None => (host_port.to_string(), 8388),
        };

        let (cipher, password) = match userinfo.split_once(':') {
            Some((c, p)) => (Some(c.to_string()), Some(p.to_string())),
            None => (None, Some(userinfo.to_string())),
        };

        let endpoint = ProxyEndpoint {
            protocol_type: Some(ProxyType::Shadowsocks),
            server,
            port,
            uuid_or_password: password,
            alter_id: None,
            cipher,
            network: Some("tcp".to_string()),
            security: None,
            sni: None,
            path: None,
            raw_link: Some(link.to_string()),
        };

        Ok((endpoint, name))
    } else {
        bail!("Invalid Shadowsocks link structure")
    }
}

pub fn parse_share_link(link: &str) -> Result<(ProxyEndpoint, Option<String>)> {
    let trimmed = link.trim();
    if trimmed.starts_with("vmess://") {
        parse_vmess(trimmed)
    } else if trimmed.starts_with("vless://") {
        parse_vless(trimmed)
    } else if trimmed.starts_with("trojan://") {
        parse_trojan(trimmed)
    } else if trimmed.starts_with("ss://") {
        parse_shadowsocks(trimmed)
    } else {
        bail!("Unsupported share link scheme: must begin with vmess://, vless://, trojan://, or ss://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vmess_valid() {
        // {"v":"2","ps":"Frankfurt VMess","add":"de.node.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"net":"ws","path":"/vmess","tls":"tls","sni":"de.node.com"}
        let raw_json = r#"{"v":"2","ps":"Frankfurt VMess","add":"de.node.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"net":"ws","path":"/vmess","tls":"tls","sni":"de.node.com"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_json);
        let link = format!("vmess://{}", b64);

        let (ep, name) = parse_share_link(&link).unwrap();
        assert_eq!(name.as_deref(), Some("Frankfurt VMess"));
        assert_eq!(ep.protocol_type, Some(ProxyType::Vmess));
        assert_eq!(ep.server, "de.node.com");
        assert_eq!(ep.port, 443);
        assert_eq!(
            ep.uuid_or_password.as_deref(),
            Some("b831381d-6324-4d53-ad4f-8cda48b30811")
        );
        assert_eq!(ep.network.as_deref(), Some("ws"));
        assert_eq!(ep.path.as_deref(), Some("/vmess"));
        assert_eq!(ep.security.as_deref(), Some("tls"));
        assert_eq!(ep.sni.as_deref(), Some("de.node.com"));
    }

    #[test]
    fn test_parse_vless_valid() {
        let link = "vless://96c8d350-f80e-4361-9f93-549b6d65c3bb@sg.node.net:443?type=ws&security=reality&sni=sg.node.net&path=%2Fvless#Singapore%20VLESS";
        let (ep, name) = parse_share_link(link).unwrap();

        assert_eq!(name.as_deref(), Some("Singapore VLESS"));
        assert_eq!(ep.protocol_type, Some(ProxyType::Vless));
        assert_eq!(ep.server, "sg.node.net");
        assert_eq!(ep.port, 443);
        assert_eq!(
            ep.uuid_or_password.as_deref(),
            Some("96c8d350-f80e-4361-9f93-549b6d65c3bb")
        );
        assert_eq!(ep.network.as_deref(), Some("ws"));
        assert_eq!(ep.security.as_deref(), Some("reality"));
        assert_eq!(ep.sni.as_deref(), Some("sg.node.net"));
        assert_eq!(ep.path.as_deref(), Some("/vless"));
    }

    #[test]
    fn test_parse_trojan_valid() {
        let link = "trojan://secretpass123@tr.node.io:443?security=tls&sni=tr.node.io#Tokyo%20Trojan";
        let (ep, name) = parse_share_link(link).unwrap();

        assert_eq!(name.as_deref(), Some("Tokyo Trojan"));
        assert_eq!(ep.protocol_type, Some(ProxyType::Trojan));
        assert_eq!(ep.server, "tr.node.io");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.uuid_or_password.as_deref(), Some("secretpass123"));
        assert_eq!(ep.security.as_deref(), Some("tls"));
        assert_eq!(ep.sni.as_deref(), Some("tr.node.io"));
    }

    #[test]
    fn test_parse_shadowsocks_sip002() {
        // chacha20-ietf-poly1305:mypassword
        let userinfo = "chacha20-ietf-poly1305:mypassword";
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(userinfo);
        let link = format!("ss://{}@us.node.org:8388#US%20East", b64);

        let (ep, name) = parse_share_link(&link).unwrap();
        assert_eq!(name.as_deref(), Some("US East"));
        assert_eq!(ep.protocol_type, Some(ProxyType::Shadowsocks));
        assert_eq!(ep.server, "us.node.org");
        assert_eq!(ep.port, 8388);
        assert_eq!(ep.cipher.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(ep.uuid_or_password.as_deref(), Some("mypassword"));
    }

    #[test]
    fn test_parse_invalid_links() {
        assert!(parse_share_link("invalid://bad-scheme").is_err());
        assert!(parse_share_link("vmess://not-valid-base64").is_err());
        assert!(parse_share_link("vless://missing-at-sign").is_err());
    }
}
