use crate::domain::config::{ProxyCore, ProxyEndpoint, ProxyRoutingMode, ProxyType};
use anyhow::{bail, Result};
use serde_json::{json, Value};

/// Generates a valid JSON configuration object for `sing-box`.
pub fn generate_singbox_config(
    endpoint: &ProxyEndpoint,
    mode: ProxyRoutingMode,
) -> Result<Value> {
    let proto = endpoint
        .protocol_type
        .unwrap_or(ProxyType::Vless);

    let mut inbounds = Vec::new();
    match mode {
        ProxyRoutingMode::SystemProxy => {
            inbounds.push(json!({
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 10808
            }));
            inbounds.push(json!({
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 10809
            }));
        }
        ProxyRoutingMode::Tun => {
            inbounds.push(json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "strict_route": true,
                "stack": "system",
                "sniff": true
            }));
        }
    }

    let proxy_outbound = match proto {
        ProxyType::Vmess => {
            let mut val = json!({
                "type": "vmess",
                "tag": "proxy",
                "server": endpoint.server,
                "server_port": endpoint.port,
                "uuid": endpoint.uuid_or_password.clone().unwrap_or_default(),
                "alter_id": endpoint.alter_id.unwrap_or(0),
                "security": endpoint.cipher.clone().unwrap_or_else(|| "auto".to_string())
            });
            if let Some(ref sec) = endpoint.security {
                if sec == "tls" || sec == "reality" {
                    val["tls"] = json!({
                        "enabled": true,
                        "server_name": endpoint.sni.clone().unwrap_or_else(|| endpoint.server.clone())
                    });
                }
            }
            if let Some(ref net) = endpoint.network {
                if net == "ws" {
                    val["transport"] = json!({
                        "type": "ws",
                        "path": endpoint.path.clone().unwrap_or_else(|| "/".to_string())
                    });
                }
            }
            val
        }
        ProxyType::Vless => {
            let mut val = json!({
                "type": "vless",
                "tag": "proxy",
                "server": endpoint.server,
                "server_port": endpoint.port,
                "uuid": endpoint.uuid_or_password.clone().unwrap_or_default()
            });
            if let Some(ref sec) = endpoint.security {
                if sec == "tls" || sec == "reality" {
                    val["tls"] = json!({
                        "enabled": true,
                        "server_name": endpoint.sni.clone().unwrap_or_else(|| endpoint.server.clone())
                    });
                }
            }
            if let Some(ref net) = endpoint.network {
                if net == "ws" {
                    val["transport"] = json!({
                        "type": "ws",
                        "path": endpoint.path.clone().unwrap_or_else(|| "/".to_string())
                    });
                }
            }
            val
        }
        ProxyType::Trojan => {
            let mut val = json!({
                "type": "trojan",
                "tag": "proxy",
                "server": endpoint.server,
                "server_port": endpoint.port,
                "password": endpoint.uuid_or_password.clone().unwrap_or_default()
            });
            val["tls"] = json!({
                "enabled": true,
                "server_name": endpoint.sni.clone().unwrap_or_else(|| endpoint.server.clone())
            });
            val
        }
        ProxyType::Shadowsocks => {
            json!({
                "type": "shadowsocks",
                "tag": "proxy",
                "server": endpoint.server,
                "server_port": endpoint.port,
                "method": endpoint.cipher.clone().unwrap_or_else(|| "chacha20-ietf-poly1305".to_string()),
                "password": endpoint.uuid_or_password.clone().unwrap_or_default()
            })
        }
        ProxyType::CustomJson => {
            bail!("CustomJson should use raw configuration file directly");
        }
    };

    let config = json!({
        "log": {
            "level": "info"
        },
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ]
    });

    Ok(config)
}

/// Generates a valid JSON configuration object for `xray` or `v2ray` (v4 schema).
pub fn generate_xray_config(
    endpoint: &ProxyEndpoint,
    mode: ProxyRoutingMode,
) -> Result<Value> {
    let proto = endpoint
        .protocol_type
        .unwrap_or(ProxyType::Vless);

    let mut inbounds = Vec::new();
    inbounds.push(json!({
        "tag": "socks-in",
        "port": 10808,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": true
        }
    }));
    inbounds.push(json!({
        "tag": "http-in",
        "port": 10809,
        "listen": "127.0.0.1",
        "protocol": "http",
        "settings": {}
    }));

    if mode == ProxyRoutingMode::Tun {
        // When xray is in TUN mode, we can add dokodemo-door or rely on tun2socks
        inbounds.push(json!({
            "tag": "tun-dokodemo",
            "port": 10807,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": true
            }
        }));
    }

    let mut stream_settings = json!({});
    if let Some(ref net) = endpoint.network {
        stream_settings["network"] = json!(net);
        if net == "ws" {
            stream_settings["wsSettings"] = json!({
                "path": endpoint.path.clone().unwrap_or_else(|| "/".to_string())
            });
        }
    }
    if let Some(ref sec) = endpoint.security {
        stream_settings["security"] = json!(sec);
        if sec == "tls" || sec == "reality" {
            stream_settings["tlsSettings"] = json!({
                "serverName": endpoint.sni.clone().unwrap_or_else(|| endpoint.server.clone())
            });
        }
    }

    let proxy_outbound = match proto {
        ProxyType::Vmess => {
            json!({
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": endpoint.server,
                        "port": endpoint.port,
                        "users": [{
                            "id": endpoint.uuid_or_password.clone().unwrap_or_default(),
                            "alterId": endpoint.alter_id.unwrap_or(0),
                            "security": endpoint.cipher.clone().unwrap_or_else(|| "auto".to_string())
                        }]
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        ProxyType::Vless => {
            json!({
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": endpoint.server,
                        "port": endpoint.port,
                        "users": [{
                            "id": endpoint.uuid_or_password.clone().unwrap_or_default(),
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        ProxyType::Trojan => {
            json!({
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": endpoint.server,
                        "port": endpoint.port,
                        "password": endpoint.uuid_or_password.clone().unwrap_or_default()
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        ProxyType::Shadowsocks => {
            json!({
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": endpoint.server,
                        "port": endpoint.port,
                        "method": endpoint.cipher.clone().unwrap_or_else(|| "chacha20-ietf-poly1305".to_string()),
                        "password": endpoint.uuid_or_password.clone().unwrap_or_default()
                    }]
                },
                "streamSettings": stream_settings
            })
        }
        ProxyType::CustomJson => {
            bail!("CustomJson should use raw configuration file directly");
        }
    };

    let config = json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            }
        ]
    });

    Ok(config)
}

/// Generates appropriate runtime configuration for given core and routing mode.
pub fn generate_runtime_config(
    core: ProxyCore,
    endpoint: &ProxyEndpoint,
    mode: ProxyRoutingMode,
) -> Result<String> {
    let json_val = match core {
        ProxyCore::SingBox => generate_singbox_config(endpoint, mode)?,
        ProxyCore::Xray | ProxyCore::V2Ray | ProxyCore::Auto => {
            // Auto defaults to sing-box if TUN mode, otherwise xray/sing-box
            if mode == ProxyRoutingMode::Tun {
                generate_singbox_config(endpoint, mode)?
            } else {
                generate_xray_config(endpoint, mode)?
            }
        }
    };
    Ok(serde_json::to_string_pretty(&json_val)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_singbox_system_proxy_and_tun() {
        let ep = ProxyEndpoint {
            protocol_type: Some(ProxyType::Vless),
            server: "sg.proxy.net".into(),
            port: 443,
            uuid_or_password: Some("11111111-2222-3333-4444-555555555555".into()),
            network: Some("ws".into()),
            security: Some("tls".into()),
            sni: Some("sg.proxy.net".into()),
            path: Some("/vless".into()),
            ..Default::default()
        };

        // System Proxy mode
        let sys_config = generate_singbox_config(&ep, ProxyRoutingMode::SystemProxy).unwrap();
        let inbounds = sys_config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[0]["listen_port"], 10808);
        assert_eq!(inbounds[1]["type"], "mixed");
        assert_eq!(inbounds[1]["listen_port"], 10809);

        // TUN mode
        let tun_config = generate_singbox_config(&ep, ProxyRoutingMode::Tun).unwrap();
        let tun_inbounds = tun_config["inbounds"].as_array().unwrap();
        assert_eq!(tun_inbounds.len(), 1);
        assert_eq!(tun_inbounds[0]["type"], "tun");
        assert_eq!(tun_inbounds[0]["auto_route"], true);
        assert_eq!(tun_inbounds[0]["interface_name"], "tun0");

        let outbounds = tun_config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["type"], "vless");
        assert_eq!(outbounds[0]["server"], "sg.proxy.net");
    }

    #[test]
    fn test_generate_xray_config_all_protocols() {
        let ep_vmess = ProxyEndpoint {
            protocol_type: Some(ProxyType::Vmess),
            server: "us.node.com".into(),
            port: 443,
            uuid_or_password: Some("uuid-1234".into()),
            alter_id: Some(0),
            cipher: Some("auto".into()),
            network: Some("ws".into()),
            security: Some("tls".into()),
            sni: Some("us.node.com".into()),
            path: Some("/ws".into()),
            ..Default::default()
        };

        let cfg = generate_xray_config(&ep_vmess, ProxyRoutingMode::SystemProxy).unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["protocol"], "vmess");
        assert_eq!(outbounds[0]["streamSettings"]["network"], "ws");
        assert_eq!(outbounds[0]["streamSettings"]["security"], "tls");

        let ep_trojan = ProxyEndpoint {
            protocol_type: Some(ProxyType::Trojan),
            server: "jp.trojan.net".into(),
            port: 443,
            uuid_or_password: Some("pass123".into()),
            security: Some("tls".into()),
            sni: Some("jp.trojan.net".into()),
            ..Default::default()
        };
        let cfg_trojan = generate_xray_config(&ep_trojan, ProxyRoutingMode::SystemProxy).unwrap();
        let outbounds_tr = cfg_trojan["outbounds"].as_array().unwrap();
        assert_eq!(outbounds_tr[0]["protocol"], "trojan");

        let ep_ss = ProxyEndpoint {
            protocol_type: Some(ProxyType::Shadowsocks),
            server: "de.ss.net".into(),
            port: 8388,
            uuid_or_password: Some("sspass".into()),
            cipher: Some("aes-256-gcm".into()),
            ..Default::default()
        };
        let cfg_ss = generate_xray_config(&ep_ss, ProxyRoutingMode::SystemProxy).unwrap();
        let outbounds_ss = cfg_ss["outbounds"].as_array().unwrap();
        assert_eq!(outbounds_ss[0]["protocol"], "shadowsocks");
    }
}
