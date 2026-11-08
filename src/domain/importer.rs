use crate::domain::account::AccountId;
use crate::domain::config::Profile;
use anyhow::Result;
use std::io::{Read, Seek};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub openvpn_count: usize,
    pub openconnect_count: usize,
    pub profiles: Vec<Profile>,
}

pub struct ProfileImporter;

impl ProfileImporter {
    /// Extracts remote endpoint (<host> <port>) from an .ovpn file content.
    pub fn parse_ovpn_remote(content: &str) -> Option<(String, u16)> {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("remote ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let host = parts[0].to_string();
                    let port = if parts.len() > 1 {
                        parts[1].parse::<u16>().unwrap_or(1194)
                    } else {
                        1194
                    };
                    return Some((host, port));
                }
            }
        }
        None
    }

    /// Derives a clean profile name from an .ovpn filename.
    pub fn clean_profile_name(filename: &str) -> String {
        let name = filename.strip_suffix(".ovpn").unwrap_or(filename);
        name.replace(['_', '-'], " ")
    }

    /// Extracts .ovpn files from a ZIP archive reader and writes them into destination folder.
    /// If generate_cisco is true, also generates matching OpenConnect profiles.
    pub fn import_zip<R: Read + Seek>(
        reader: R,
        dest_ovpn_dir: &Path,
        target_account_id: Option<AccountId>,
        generate_cisco: bool,
    ) -> Result<ImportSummary> {
        let mut archive = zip::ZipArchive::new(reader)?;
        let mut profiles = Vec::new();
        let mut ovpn_count = 0;
        let mut oc_count = 0;

        std::fs::create_dir_all(dest_ovpn_dir)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.is_dir() {
                continue;
            }
            let filename = match file.enclosed_name() {
                Some(p) => p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string(),
                None => continue,
            };

            if filename.ends_with(".ovpn") {
                let mut content = String::new();
                file.read_to_string(&mut content)?;

                let target_file_path = dest_ovpn_dir.join(&filename);
                std::fs::write(&target_file_path, &content)?;

                let (host, port) = Self::parse_ovpn_remote(&content)
                    .unwrap_or_else(|| ("unknown.gateway".into(), 1194));
                let endpoint = format!("{}:{}", host, port);
                let base_name = Self::clean_profile_name(&filename);

                // 1. Create OpenVPN profile
                let mut ov_profile = Profile::new_openvpn(
                    format!("{} (OVPN)", base_name),
                    &endpoint,
                    Some(target_file_path),
                )
                .with_group("BioVPN/OpenVPN");
                if let Some(ref acc_id) = target_account_id {
                    ov_profile = ov_profile.with_account(acc_id.clone());
                }
                profiles.push(ov_profile);
                ovpn_count += 1;

                // 2. Optionally create Cisco OpenConnect profile
                if generate_cisco {
                    let oc_endpoint = if port == 1194 {
                        format!("{}:443", host)
                    } else {
                        endpoint.clone()
                    };
                    let mut oc_profile =
                        Profile::new_openconnect(format!("{} (Cisco)", base_name), &oc_endpoint)
                            .with_group("BioVPN/Cisco");
                    if let Some(ref acc_id) = target_account_id {
                        oc_profile = oc_profile.with_account(acc_id.clone());
                    }
                    profiles.push(oc_profile);
                    oc_count += 1;
                }
            }
        }

        Ok(ImportSummary {
            openvpn_count: ovpn_count,
            openconnect_count: oc_count,
            profiles,
        })
    }

    /// Parses batch text with server entries (e.g. "NL 45.93.169.132" or "Germany vpn.corp.de:443")
    pub fn parse_server_list(
        text: &str,
        target_account_id: Option<AccountId>,
    ) -> Result<Vec<Profile>> {
        let mut profiles = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0..parts.len() - 1].join(" ");
            let mut endpoint = parts[parts.len() - 1].to_string();
            if !endpoint.contains(':') {
                endpoint = format!("{}:443", endpoint);
            }

            let mut profile = Profile::new_openconnect(&name, &endpoint).with_group("BioVPN/Cisco");
            if let Some(ref acc_id) = target_account_id {
                profile = profile.with_account(acc_id.clone());
            }
            profiles.push(profile);
        }
        Ok(profiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn test_parse_ovpn_remote() {
        let sample = "client\ndev tun\n# Comment\nremote 45.93.169.132 1194\nproto udp";
        let res = ProfileImporter::parse_ovpn_remote(sample);
        assert_eq!(res, Some(("45.93.169.132".to_string(), 1194)));

        let sample_no_port = "client\nremote vpn.corp.net\n";
        let res2 = ProfileImporter::parse_ovpn_remote(sample_no_port);
        assert_eq!(res2, Some(("vpn.corp.net".to_string(), 1194)));
    }

    #[test]
    fn test_parse_server_list() {
        let text = r#"
            # Server endpoints
            Netherlands 45.93.169.132
            Poland VIP 51.83.177.109:8443
            Germany de.biovpn.net
        "#;
        let acc_id = AccountId::new("test_acc");
        let profiles = ProfileImporter::parse_server_list(text, Some(acc_id.clone())).unwrap();
        assert_eq!(profiles.len(), 3);

        assert_eq!(profiles[0].name, "Netherlands");
        assert_eq!(profiles[0].endpoint, "45.93.169.132:443");
        assert_eq!(profiles[0].account_id.as_ref(), Some(&acc_id));
        assert_eq!(profiles[0].group.as_deref(), Some("BioVPN/Cisco"));

        assert_eq!(profiles[1].name, "Poland VIP");
        assert_eq!(profiles[1].endpoint, "51.83.177.109:8443");
        assert_eq!(profiles[1].group.as_deref(), Some("BioVPN/Cisco"));

        assert_eq!(profiles[2].name, "Germany");
        assert_eq!(profiles[2].endpoint, "de.biovpn.net:443");
        assert_eq!(profiles[2].group.as_deref(), Some("BioVPN/Cisco"));
    }

    #[test]
    fn test_import_zip_with_cisco_generation() {
        let temp_dir = tempdir().unwrap();
        let ovpn_dest = temp_dir.path().join("openvpn");

        // Create an in-memory zip
        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut zip_buf);
            let options = SimpleFileOptions::default();

            writer.start_file("NL_Amsterdam.ovpn", options).unwrap();
            writer
                .write_all(b"client\ndev tun\nremote 45.93.169.132 1194\n")
                .unwrap();

            writer.start_file("PL_Warsaw.ovpn", options).unwrap();
            writer
                .write_all(b"client\ndev tun\nremote 45.252.182.34 443\n")
                .unwrap();

            writer.finish().unwrap();
        }

        zip_buf.set_position(0);
        let acc = AccountId::new("hosenbio");
        let summary = ProfileImporter::import_zip(zip_buf, &ovpn_dest, Some(acc), true).unwrap();

        assert_eq!(summary.openvpn_count, 2);
        assert_eq!(summary.openconnect_count, 2);
        assert_eq!(summary.profiles.len(), 4);

        // Verify extracted files exist
        assert!(ovpn_dest.join("NL_Amsterdam.ovpn").exists());
        assert!(ovpn_dest.join("PL_Warsaw.ovpn").exists());

        // Verify OpenConnect profile derived from remote
        let oc_nl = summary
            .profiles
            .iter()
            .find(|p| {
                p.name.contains("NL Amsterdam")
                    && p.protocol == crate::domain::config::VpnProtocol::OpenConnect
            })
            .unwrap();
        assert_eq!(oc_nl.endpoint, "45.93.169.132:443");
        assert_eq!(oc_nl.group.as_deref(), Some("BioVPN/Cisco"));

        let ov_nl = summary
            .profiles
            .iter()
            .find(|p| {
                p.name.contains("NL Amsterdam")
                    && p.protocol == crate::domain::config::VpnProtocol::OpenVpn
            })
            .unwrap();
        assert_eq!(ov_nl.group.as_deref(), Some("BioVPN/OpenVPN"));
    }
}
