use crate::error::Result;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub ip_address: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub routes: Vec<Route>,
    pub idle_timeout: Option<u32>,
    pub auth_timeout: Option<u32>,
    pub dtls_port: Option<u16>,
    pub fos_version: Option<String>,
    pub tunnel_method: String,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl TunnelConfig {
    pub fn parse(xml: &str) -> Result<Self> {
        let ip_address = extract_tag_attr(xml, "assigned-addr", "ipv4")
            .or_else(|| extract_text(xml, "assigned-addr"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        let mut dns_servers = Vec::new();
        // Attribute format: <dns ip="..."/>
        if let Some(dns1) = extract_tag_attr(xml, "dns", "ip") {
            if let Ok(addr) = dns1.parse() { dns_servers.push(addr); }
        }
        // Attribute format: <dns2 ip="..."/>
        if let Some(dns2) = extract_tag_attr(xml, "dns2", "ip") {
            if let Ok(addr) = dns2.parse() { dns_servers.push(addr); }
        }
        // Fallback: text format <dns>x.x.x.x</dns>
        if dns_servers.is_empty() {
            if let Some(dns1) = extract_text(xml, "dns") {
                if let Ok(addr) = dns1.parse() { dns_servers.push(addr); }
            }
            if let Some(dns2) = extract_text(xml, "dns2") {
                if let Ok(addr) = dns2.parse() { dns_servers.push(addr); }
            }
        }

        let mut routes = Vec::new();
        for addr_match in find_all_tag_attrs(xml, "addr") {
            if let (Some(ip_str), Some(mask_str)) = (addr_match.get("ip"), addr_match.get("mask")) {
                if let (Ok(ip), Ok(mask)) = (ip_str.parse(), mask_str.parse()) {
                    routes.push(Route { ip, mask });
                }
            }
        }

        let idle_timeout = extract_text(xml, "idle-timeout").and_then(|s| s.parse().ok());
        let auth_timeout = extract_text(xml, "auth-timeout").and_then(|s| s.parse().ok());
        let dtls_port = extract_text(xml, "dtls-config")
            .and_then(|s| extract_text(&s, "port"))
            .and_then(|s| s.parse().ok());
        let fos_version = extract_text(xml, "fos");
        let tunnel_method = extract_tag_attr(xml, "tunnel-method", "value")
            .unwrap_or_else(|| "ppp".to_string());

        Ok(Self { ip_address, dns_servers, routes, idle_timeout, auth_timeout, dtls_port, fos_version, tunnel_method })
    }
}

/// Check that the character after the tag name is a valid tag-name terminator
/// (whitespace, `>`, `/`, or end-of-string). This prevents `<dns` from matching `<dns2>`.
fn is_tag_boundary(c: Option<char>) -> bool {
    match c {
        None => true,
        Some(ch) => ch.is_whitespace() || ch == '>' || ch == '/',
    }
}

fn extract_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find(&open) {
        let abs_pos = search_from + pos;
        let after_open = &xml[abs_pos + open.len()..];
        if !is_tag_boundary(after_open.chars().next()) {
            search_from = abs_pos + open.len();
            continue;
        }
        let content_start = after_open.find('>')? + 1;
        let content = &after_open[content_start..];
        let end_idx = content.find(&close)?;
        let text = content[..end_idx].trim().to_string();
        return if text.is_empty() { None } else { Some(text) };
    }
    None
}

fn extract_tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find(&open) {
        let abs_pos = search_from + pos;
        let after_open = &xml[abs_pos + open.len()..];
        if !is_tag_boundary(after_open.chars().next()) {
            search_from = abs_pos + open.len();
            continue;
        }
        let tag_end = after_open.find('>')?;
        let tag_content = &after_open[..tag_end];
        let attr_pattern = format!("{}=\"", attr);
        if let Some(attr_start) = tag_content.find(&attr_pattern) {
            let value_start = attr_start + attr_pattern.len();
            let value_end = tag_content[value_start..].find('"')?;
            return Some(tag_content[value_start..value_start + value_end].to_string());
        }
        search_from = abs_pos + open.len();
    }
    None
}

fn find_all_tag_attrs(xml: &str, tag: &str) -> Vec<std::collections::HashMap<String, String>> {
    let open = format!("<{}", tag);
    let mut results = Vec::new();
    let mut search_from = 0;

    while let Some(pos) = xml[search_from..].find(&open) {
        let abs_pos = search_from + pos;
        let after_open = &xml[abs_pos + open.len()..];
        if !is_tag_boundary(after_open.chars().next()) {
            search_from = abs_pos + open.len();
            continue;
        }
        if let Some(tag_end) = after_open.find('>') {
            let tag_content = &after_open[..tag_end];
            let mut attrs = std::collections::HashMap::new();
            let mut remaining = tag_content;
            while let Some(eq_pos) = remaining.find("=\"") {
                let before_eq = &remaining[..eq_pos];
                let attr_name = before_eq.rsplit_once(char::is_whitespace)
                    .map(|(_, name)| name)
                    .unwrap_or(before_eq)
                    .trim();
                let value_start = eq_pos + 2;
                if let Some(value_end) = remaining[value_start..].find('"') {
                    let value = &remaining[value_start..value_start + value_end];
                    attrs.insert(attr_name.to_string(), value.to_string());
                    remaining = &remaining[value_start + value_end + 1..];
                } else { break; }
            }
            if !attrs.is_empty() { results.push(attrs); }
            search_from = abs_pos + open.len() + tag_end;
        } else { break; }
    }
    results
}
