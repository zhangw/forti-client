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
        // Collect all <dns ip="..."/> entries
        for attrs in find_all_tag_attrs(xml, "dns") {
            if let Some(ip_str) = attrs.get("ip") {
                if let Ok(addr) = ip_str.parse() { dns_servers.push(addr); }
            }
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

        let idle_timeout = extract_tag_attr(xml, "idle-timeout", "val")
            .or_else(|| extract_text(xml, "idle-timeout"))
            .and_then(|s| s.parse().ok());
        let auth_timeout = extract_tag_attr(xml, "auth-timeout", "val")
            .or_else(|| extract_text(xml, "auth-timeout"))
            .and_then(|s| s.parse().ok());
        let dtls_port = extract_text(xml, "dtls-config")
            .and_then(|s| extract_text(&s, "port"))
            .and_then(|s| s.parse().ok());
        let fos_version = extract_text(xml, "fos");
        let tunnel_method = extract_tag_attr(xml, "tunnel-method", "value")
            .unwrap_or_else(|| "ppp".to_string());

        Ok(Self { ip_address, dns_servers, routes, idle_timeout, auth_timeout, dtls_port, fos_version, tunnel_method })
    }
}

/// Check that the character after the tag name is a valid tag-name terminator.
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

/// Extract a specific attribute value from a tag, supporting both single and double quotes.
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
        if let Some(value) = find_attr_value(tag_content, attr) {
            return Some(value);
        }
        search_from = abs_pos + open.len();
    }
    None
}

/// Find all occurrences of a tag and extract their attributes (supports single and double quotes).
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
            let attrs = parse_all_attrs(tag_content);
            if !attrs.is_empty() { results.push(attrs); }
            search_from = abs_pos + open.len() + tag_end;
        } else { break; }
    }
    results
}

/// Find the value of a specific attribute, supporting both `attr="val"` and `attr='val'`.
fn find_attr_value(tag_content: &str, attr: &str) -> Option<String> {
    // Try double quotes
    let dq_pattern = format!("{}=\"", attr);
    if let Some(start) = tag_content.find(&dq_pattern) {
        let value_start = start + dq_pattern.len();
        if let Some(value_end) = tag_content[value_start..].find('"') {
            return Some(tag_content[value_start..value_start + value_end].to_string());
        }
    }
    // Try single quotes
    let sq_pattern = format!("{}='", attr);
    if let Some(start) = tag_content.find(&sq_pattern) {
        let value_start = start + sq_pattern.len();
        if let Some(value_end) = tag_content[value_start..].find('\'') {
            return Some(tag_content[value_start..value_start + value_end].to_string());
        }
    }
    None
}

/// Parse all attributes from tag content, supporting both quote styles.
fn parse_all_attrs(tag_content: &str) -> std::collections::HashMap<String, String> {
    let mut attrs = std::collections::HashMap::new();
    let mut remaining = tag_content;

    while !remaining.is_empty() {
        // Find the next = sign
        let eq_pos = match remaining.find('=') {
            Some(p) => p,
            None => break,
        };

        // Extract attribute name (word before =)
        let before_eq = &remaining[..eq_pos];
        let attr_name = before_eq.rsplit_once(char::is_whitespace)
            .map(|(_, name)| name)
            .unwrap_or(before_eq)
            .trim();

        // Check what quote character follows =
        let after_eq = &remaining[eq_pos + 1..];
        let quote_char = match after_eq.chars().next() {
            Some(c @ '"') | Some(c @ '\'') => c,
            _ => { remaining = &remaining[eq_pos + 1..]; continue; }
        };

        let value_start = 1; // skip the opening quote
        if let Some(value_end) = after_eq[value_start..].find(quote_char) {
            let value = &after_eq[value_start..value_start + value_end];
            if !attr_name.is_empty() {
                attrs.insert(attr_name.to_string(), value.to_string());
            }
            remaining = &after_eq[value_start + value_end + 1..];
        } else {
            break;
        }
    }

    attrs
}
