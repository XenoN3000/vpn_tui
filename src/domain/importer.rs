use crate::domain::account::AccountId;
use crate::domain::config::{Profile, ProfileId};
use anyhow::Result;
use std::io::{Read, Seek};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub openvpn_count: usize,
    pub openconnect_count: usize,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPortalServer {
    pub name: String,
    pub endpoint: String,
    pub group: String,
    pub country_group: String,
    pub ovpn_download_url: Option<String>,
}

impl ParsedPortalServer {
    pub fn cisco_group(&self) -> String {
        format!("BioVPN/Cisco/{}", self.country_group)
    }

    pub fn openvpn_group(&self) -> String {
        format!("BioVPN/OpenVPN/{}", self.country_group)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortalHtmlImportResult {
    pub profiles: Vec<Profile>,
    pub servers: Vec<ParsedPortalServer>,
    pub groups: Vec<String>,
    pub zip_download_url: Option<String>,
}

pub const COUNTRY_TRANSLATIONS: [(&str, &str); 15] = [
    ("سرور های هوشمند کلیه کشور ها", "Smart All Country"),
    ("سرور های سری FI-DE-FR-PL-SW", "OVH Series"),
    ("انگلیس", "United Kingdom"),
    ("هلند", "Netherlands"),
    ("آلمان", "Germany"),
    ("فنلاند", "Finland"),
    ("لهستان", "Poland"),
    ("فرانسه", "France"),
    ("کانادا", "Canada"),
    ("ایتالیا", "Italy"),
    ("بلژیک", "Belgium"),
    ("اتریش", "Austria"),
    ("سوئیس", "Switzerland"),
    ("اسپانیا", "Spain"),
    ("آمریکا", "USA"),
];

/// Translates a portal group title to English if present in the dictionary;
/// otherwise returns the cleaned original title.
pub fn translate_group_name(raw: &str) -> String {
    let cleaned = raw
        .replace('+', "")
        .replace("برای نمایش لیست سرورها کلیک کنید", "")
        .trim()
        .to_string();

    if cleaned.is_empty() {
        return "Default".to_string();
    }

    for (persian, english) in COUNTRY_TRANSLATIONS {
        if cleaned.contains(persian) || persian.contains(&cleaned) {
            return english.to_string();
        }
    }

    cleaned
}

/// Helper to strip HTML tags and decode common XML/HTML entities.
fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut inside = false;
    for ch in input.chars() {
        if ch == '<' {
            inside = true;
        } else if ch == '>' {
            inside = false;
        } else if !inside {
            out.push(ch);
        }
    }
    out.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .trim()
        .to_string()
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

    /// Derives a safe filename for a downloaded OpenVPN config from URL, country group, and server name.
    pub fn derive_ovpn_filename(url: &str, country_group: &str, server_name: &str) -> String {
        let server_val = if let Some(idx) = url.find("server=") {
            let after = &url[idx + 7..];
            let end = after.find('&').unwrap_or(after.len());
            let val = &after[..end];
            if !val.is_empty() { Some(val) } else { None }
        } else {
            None
        };

        if let Some(s) = server_val {
            let sanitized: String = s
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            if sanitized.ends_with(".ovpn") {
                sanitized
            } else {
                format!("{}.ovpn", sanitized)
            }
        } else {
            let raw = format!("{}_{}", country_group, server_name);
            let sanitized: String = raw
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("{}.ovpn", sanitized)
        }
    }

    /// Constructs an OpenVPN Profile from downloaded table config content and metadata.
    pub fn create_table_openvpn_profile(
        server_name: &str,
        country_group: &str,
        ovpn_content: &str,
        file_path: &Path,
        target_account_id: Option<AccountId>,
    ) -> Profile {
        let (host, port) = Self::parse_ovpn_remote(ovpn_content)
            .unwrap_or_else(|| ("unknown.gateway".into(), 1194));
        let endpoint = format!("{}:{}", host, port);
        let display_name = format!("{} (OVPN)", server_name);
        let folder_group = format!("BioVPN/OpenVPN/{}", country_group);

        let raw_id = format!("ovpn-{}-{}-{}", country_group, server_name, endpoint);
        let slug = raw_id
            .to_lowercase()
            .replace(' ', "-")
            .replace(':', "-")
            .replace('.', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        let clean_slug = slug
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let profile_id = ProfileId::new(clean_slug);

        let mut profile =
            Profile::new_openvpn(display_name, &endpoint, Some(file_path.to_path_buf()))
                .with_group(&folder_group)
                .with_inherit_defaults(true);
        profile.id = profile_id;

        if let Some(acc_id) = target_account_id {
            profile = profile.with_account(acc_id);
        }

        profile
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
                .with_group("BioVPN/OpenVPN")
                .with_inherit_defaults(true);
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
                            .with_group("BioVPN/Cisco")
                            .with_inherit_defaults(true);
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

    /// Parses BioVPN portal dashboard HTML table and extracts categorized Cisco AnyConnect profiles
    /// and OpenVPN download links with guaranteed unique IDs.
    pub fn parse_portal_html(
        html: &str,
        target_account_id: Option<AccountId>,
        base_url: Option<&str>,
    ) -> Result<PortalHtmlImportResult> {
        let mut profiles = Vec::new();
        let mut servers = Vec::new();
        let mut groups = Vec::new();
        let mut current_group = "General".to_string();

        let base = base_url
            .unwrap_or("https://n1buy.info")
            .trim_end_matches('/');

        // 1. Check for global zip download link
        let mut zip_download_url = None;
        let mut search_idx = 0;
        let bytes = html.as_bytes();
        while let Some(pos) = html[search_idx..].find("href=") {
            let start = search_idx + pos + 5;
            search_idx = start;
            if start >= bytes.len() {
                break;
            }
            let quote = bytes[start];
            if quote == b'"' || quote == b'\'' {
                if let Some(end_quote) = html[start + 1..].find(quote as char) {
                    let link = &html[start + 1..start + 1 + end_quote].trim();
                    let lower = link.to_lowercase();
                    if lower.ends_with(".zip")
                        && !lower.contains("smart-bio")
                        && !lower.contains("app")
                        && !lower.contains("setup")
                        && !lower.contains("2client")
                        && (lower.contains("smarttcp")
                            || lower.contains("openvpn")
                            || lower.contains("config"))
                    {
                        let full = if link.starts_with("http://") || link.starts_with("https://") {
                            link.to_string()
                        } else {
                            format!("{}/{}", base, link.trim_start_matches('/'))
                        };
                        zip_download_url = Some(full);
                        break;
                    }
                }
            }
        }

        // 2. Parse <tr> rows
        let mut tr_start = 0;
        while let Some(start_pos) = html[tr_start..].find("<tr") {
            let abs_start = tr_start + start_pos;
            let end_tag = match html[abs_start..].find("</tr>") {
                Some(end_pos) => abs_start + end_pos + 5,
                None => break,
            };
            let row_html = &html[abs_start..end_tag];
            tr_start = end_tag;

            let row_lower = row_html.to_lowercase();

            // Check if group toggle row
            if row_lower.contains("bio-server-group-toggle")
                || (row_lower.contains("colspan") && row_lower.contains("<th"))
            {
                if let Some(th_start) = row_html.find("<th") {
                    if let Some(th_content_start) = row_html[th_start..].find('>') {
                        let th_abs = th_start + th_content_start + 1;
                        if let Some(th_end) = row_html[th_abs..].find("</th>") {
                            let raw_title = &row_html[th_abs..th_abs + th_end];
                            let cleaned_text = strip_html_tags(raw_title);
                            let translated = translate_group_name(&cleaned_text);
                            if !translated.is_empty() {
                                current_group = translated;
                                if !groups.contains(&current_group) {
                                    groups.push(current_group.clone());
                                }
                            }
                        }
                    }
                }
                continue;
            }

            // Check if server child row
            if row_lower.contains("bio-server-child-row")
                || (row_lower.contains("<th") && row_lower.contains("<td"))
            {
                let mut server_name = String::new();
                let mut server_address = String::new();
                let mut ovpn_url = None;

                // Extract TH (server name)
                if let Some(th_start) = row_html.find("<th") {
                    if let Some(gt) = row_html[th_start..].find('>') {
                        let content_start = th_start + gt + 1;
                        if let Some(th_end) = row_html[content_start..].find("</th>") {
                            server_name =
                                strip_html_tags(&row_html[content_start..content_start + th_end]);
                        }
                    }
                }

                // Extract Address (server-address span or first TD)
                if let Some(span_pos) = row_html.find("server-address") {
                    if let Some(gt) = row_html[span_pos..].find('>') {
                        let content_start = span_pos + gt + 1;
                        if let Some(span_end) = row_html[content_start..].find("</span>") {
                            server_address =
                                strip_html_tags(&row_html[content_start..content_start + span_end]);
                        }
                    }
                }

                if server_address.is_empty() {
                    if let Some(td_start) = row_html.find("<td") {
                        if let Some(gt) = row_html[td_start..].find('>') {
                            let content_start = td_start + gt + 1;
                            if let Some(td_end) = row_html[content_start..].find("</td>") {
                                let td_text = strip_html_tags(
                                    &row_html[content_start..content_start + td_end],
                                );
                                for token in td_text.split_whitespace() {
                                    if token.contains('.') {
                                        server_address = token.to_string();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Extract OpenVPN download link
                if let Some(link_pos) = row_html.find("download_ovpn") {
                    // Backtrack to href="
                    if let Some(href_pos) = row_html[..link_pos].rfind("href=") {
                        let quote_pos = href_pos + 5;
                        if quote_pos < row_html.len() {
                            let quote = row_html.as_bytes()[quote_pos];
                            if quote == b'"' || quote == b'\'' {
                                if let Some(end_quote) =
                                    row_html[quote_pos + 1..].find(quote as char)
                                {
                                    let raw_link =
                                        &row_html[quote_pos + 1..quote_pos + 1 + end_quote];
                                    let unescaped = raw_link.replace("&amp;", "&");
                                    let full_link = if unescaped.starts_with("http://")
                                        || unescaped.starts_with("https://")
                                    {
                                        unescaped
                                    } else {
                                        format!("{}/{}", base, unescaped.trim_start_matches('/'))
                                    };
                                    ovpn_url = Some(full_link);
                                }
                            }
                        }
                    }
                }

                if !server_name.is_empty() && !server_address.is_empty() {
                    let mut endpoint = server_address.trim().to_string();
                    if !endpoint.contains(':') {
                        endpoint = format!("{}:443", endpoint);
                    }

                    let host_only = endpoint.split(':').next().unwrap_or(&endpoint);
                    let host_tag = host_only.split('.').next().unwrap_or(host_only);

                    let display_name = if server_name
                        .to_lowercase()
                        .contains(&host_tag.to_lowercase())
                    {
                        format!("{} (Cisco)", server_name)
                    } else {
                        format!("{} ({}) (Cisco)", server_name, host_tag)
                    };

                    let folder_group = format!("BioVPN/Cisco/{}", current_group);

                    // Build deterministic, collision-free unique profile ID combining group, name, and endpoint
                    let raw_id = format!("{}-{}-{}", current_group, server_name, endpoint);
                    let slug = raw_id
                        .to_lowercase()
                        .replace(' ', "-")
                        .replace(':', "-")
                        .replace('.', "-")
                        .chars()
                        .filter(|c| c.is_alphanumeric() || *c == '-')
                        .collect::<String>();
                    let clean_slug = slug
                        .split('-')
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join("-");
                    let profile_id = ProfileId::new(format!("{}-cisco", clean_slug));

                    let mut profile = Profile::new_openconnect(&display_name, &endpoint)
                        .with_group(&folder_group)
                        .with_inherit_defaults(true);
                    profile.id = profile_id;

                    if let Some(ref acc_id) = target_account_id {
                        profile = profile.with_account(acc_id.clone());
                    }

                    profiles.push(profile);
                    servers.push(ParsedPortalServer {
                        name: server_name,
                        endpoint,
                        group: folder_group,
                        country_group: current_group.clone(),
                        ovpn_download_url: ovpn_url,
                    });
                }
            }
        }

        Ok(PortalHtmlImportResult {
            profiles,
            servers,
            groups,
            zip_download_url,
        })
    }

    /// Parses batch text with server entries (e.g. "NL 45.93.169.132" or "Germany vpn.corp.de:443")
    /// or automatically processes full/partial portal HTML tables.
    pub fn parse_server_list(
        text: &str,
        target_account_id: Option<AccountId>,
    ) -> Result<Vec<Profile>> {
        let trimmed = text.trim();
        if trimmed.contains("<table") || trimmed.contains("<tr") || trimmed.contains("bio-server") {
            let res = Self::parse_portal_html(trimmed, target_account_id, None)?;
            return Ok(res.profiles);
        }

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

            let mut profile = Profile::new_openconnect(&name, &endpoint)
                .with_group("BioVPN/Cisco")
                .with_inherit_defaults(true);
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
        assert!(summary.profiles.iter().all(|p| p.inherit_defaults));

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

    #[test]
    fn test_translate_group_name_known_and_fallback() {
        assert_eq!(
            translate_group_name("+ سرور های هوشمند کلیه کشور ها برای نمایش لیست سرورها کلیک کنید"),
            "Smart All Country"
        );
        assert_eq!(translate_group_name("هلند"), "Netherlands");
        assert_eq!(translate_group_name("آلمان"), "Germany");
        assert_eq!(translate_group_name("انگلیس"), "United Kingdom");
        assert_eq!(
            translate_group_name("سرور های سری FI-DE-FR-PL-SW"),
            "OVH Series"
        );
        assert_eq!(
            translate_group_name("سرور اختصاصی تهران"),
            "سرور اختصاصی تهران"
        );
        assert_eq!(translate_group_name(""), "Default");
    }

    #[test]
    fn test_parse_portal_html() {
        let sample_html = r#"
            <div id="accordion-tab-regular-2">
                <a href="/dl/BioVPN-SmartTCP.zip">Download Zip</a>
                <table class="table table-bordered text-center table-layout-fixed">
                    <tbody>
                        <tr class="bio-server-group-toggle">
                            <th colspan="3">
                                <span class="bio-server-group-icon">+</span>
                                سرور های هوشمند کلیه کشور ها
                                <span class="bio-server-group-hint">برای نمایش لیست سرورها کلیک کنید</span>
                            </th>
                        </tr>
                        <tr class="bio-server-child-row">
                            <th>هلند هوشمند</th>
                            <td>
                                <span class="server-address" onclick="copyToClipboard('NL1.cdntak.com', event)">NL1.cdntak.com</span>
                            </td>
                            <td>
                                <a class="bio-ovpn-download" href="https://n1buy.info/clientarea/index.php?download_ovpn=1&amp;server=OPNL.cdntak.com">دانلود کانفیگ</a>
                            </td>
                        </tr>
                        <tr class="bio-server-child-row">
                            <th>هلند هوشمند</th>
                            <td>
                                <span class="server-address">NL2.cdntak.com</span>
                            </td>
                            <td></td>
                        </tr>
                        <tr class="bio-server-child-row">
                            <th>آلمان هوشمند</th>
                            <td>
                                <span class="server-address">de1.cdntak.com:110</span>
                            </td>
                            <td></td>
                        </tr>
                        <tr class="bio-server-group-toggle">
                            <th colspan="3">انگلیس</th>
                        </tr>
                        <tr class="bio-server-child-row">
                            <th>لندن 1</th>
                            <td>
                                <span class="server-address">cfuk1.cdntak.com</span>
                            </td>
                            <td>
                                <a class="bio-ovpn-download" href="/clientarea/index.php?download_ovpn=1&amp;server=OPUK.cdntak.com">دانلود کانفیگ</a>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        "#;

        let acc_id = AccountId::new("testacc");
        let result = ProfileImporter::parse_portal_html(
            sample_html,
            Some(acc_id.clone()),
            Some("https://n1buy.info"),
        )
        .unwrap();

        assert_eq!(result.groups, vec!["Smart All Country", "United Kingdom"]);
        assert_eq!(result.profiles.len(), 4);
        assert_eq!(result.servers.len(), 4);
        assert!(result.profiles.iter().all(|p| p.inherit_defaults));
        assert_eq!(
            result.zip_download_url,
            Some("https://n1buy.info/dl/BioVPN-SmartTCP.zip".to_string())
        );

        // Verify duplicate names get distinct host tags in display names and unique IDs
        let p0 = &result.profiles[0];
        assert_eq!(p0.name, "هلند هوشمند (NL1) (Cisco)");
        assert_eq!(p0.endpoint, "NL1.cdntak.com:443");
        assert_eq!(p0.group.as_deref(), Some("BioVPN/Cisco/Smart All Country"));

        let p1 = &result.profiles[1];
        assert_eq!(p1.name, "هلند هوشمند (NL2) (Cisco)");
        assert_eq!(p1.endpoint, "NL2.cdntak.com:443");
        assert_eq!(p1.group.as_deref(), Some("BioVPN/Cisco/Smart All Country"));

        // IDs must be distinct
        assert_ne!(p0.id, p1.id);

        let p2 = &result.profiles[2];
        assert_eq!(p2.name, "آلمان هوشمند (de1) (Cisco)");
        assert_eq!(p2.endpoint, "de1.cdntak.com:110");
        assert_eq!(p2.group.as_deref(), Some("BioVPN/Cisco/Smart All Country"));

        let p3 = &result.profiles[3];
        assert_eq!(p3.name, "لندن 1 (cfuk1) (Cisco)");
        assert_eq!(p3.endpoint, "cfuk1.cdntak.com:443");
        assert_eq!(p3.group.as_deref(), Some("BioVPN/Cisco/United Kingdom"));
    }

    #[test]
    fn test_parse_server_list_auto_detects_html() {
        let snippet = r#"
            <table class="table">
                <tr class="bio-server-group-toggle"><th>آلمان</th></tr>
                <tr class="bio-server-child-row">
                    <th>Frankfurt 1</th>
                    <td><span class="server-address">de.corp.com</span></td>
                </tr>
            </table>
        "#;
        let profiles = ProfileImporter::parse_server_list(snippet, None).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "Frankfurt 1 (de) (Cisco)");
        assert_eq!(profiles[0].endpoint, "de.corp.com:443");
        assert_eq!(profiles[0].group.as_deref(), Some("BioVPN/Cisco/Germany"));
    }

    #[test]
    fn test_derive_ovpn_filename_and_create_table_profile() {
        let url = "https://n1buy.info/clientarea/index.php?download_ovpn=1&server=OPNL.cdntak.com";
        let filename = ProfileImporter::derive_ovpn_filename(url, "Netherlands", "NL1");
        assert_eq!(filename, "OPNL.cdntak.com.ovpn");

        let url_no_param = "/clientarea/index.php?download=direct";
        let filename2 = ProfileImporter::derive_ovpn_filename(url_no_param, "Netherlands", "NL 1");
        assert_eq!(filename2, "Netherlands_NL_1.ovpn");

        let ovpn_content = "client\ndev tun\nremote 45.93.169.132 1194\n";
        let file_path = Path::new("/test/path/OPNL.ovpn");
        let acc_id = AccountId::new("testacc");
        let prof = ProfileImporter::create_table_openvpn_profile(
            "NL1",
            "Netherlands",
            ovpn_content,
            file_path,
            Some(acc_id.clone()),
        );

        assert_eq!(prof.name, "NL1 (OVPN)");
        assert_eq!(prof.endpoint, "45.93.169.132:1194");
        assert_eq!(prof.group.as_deref(), Some("BioVPN/OpenVPN/Netherlands"));
        assert_eq!(prof.account_id.as_ref(), Some(&acc_id));
        assert_eq!(prof.ovpn_file, Some(file_path.to_path_buf()));
        assert!(prof.inherit_defaults);
    }
}
