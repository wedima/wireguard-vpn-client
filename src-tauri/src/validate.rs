//! Strict checks for values that are later passed to privileged network tools.
//!
//! WireGuard configs are parsed and then handed to `route`, `netsh`, and
//! PowerShell. Those commands run as the helper. Rejecting anything that is
//! not an address, CIDR, DNS name, or endpoint keeps a malicious config from
//! changing the command that actually runs.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::wg_config::WgConfig;

pub fn validate_config(cfg: &WgConfig) -> Result<(), String> {
    if cfg.interface.addresses.is_empty() {
        return Err("Interface has no Address".into());
    }
    for address in &cfg.interface.addresses {
        validate_ip_or_cidr(address)?;
    }
    for dns in &cfg.interface.dns {
        validate_dns(dns)?;
    }
    if !(576..=65535).contains(&cfg.interface.mtu) {
        return Err("Invalid MTU".into());
    }
    if cfg.peers.is_empty() {
        return Err("WireGuard config has no [Peer] section".into());
    }
    for peer in &cfg.peers {
        if let Some(endpoint) = &peer.endpoint {
            validate_endpoint(endpoint)?;
        }
        for allowed in &peer.allowed_ips {
            validate_ip_or_cidr(allowed)?;
        }
    }
    if let Some(name) = &cfg.name {
        if name.chars().count() > 80 || name.chars().any(|c| c.is_control()) {
            return Err("Invalid connection name".into());
        }
    }
    Ok(())
}

pub fn validate_ip_or_cidr(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || value.chars().any(|c| c.is_whitespace()) {
        return Err("Invalid address".into());
    }
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (value, None),
    };
    if addr.contains(':') {
        if addr.parse::<Ipv6Addr>().is_err() {
            return Err("Invalid address".into());
        }
        if let Some(prefix) = prefix {
            let bits: u8 = prefix.parse().map_err(|_| "Invalid prefix".to_string())?;
            if bits > 128 {
                return Err("Invalid prefix".into());
            }
        }
    } else if addr.parse::<Ipv4Addr>().is_err() {
        return Err("Invalid address".into());
    } else if let Some(prefix) = prefix {
        let bits: u8 = prefix.parse().map_err(|_| "Invalid prefix".to_string())?;
        if bits > 32 {
            return Err("Invalid prefix".into());
        }
    }
    Ok(())
}

pub fn validate_dns(value: &str) -> Result<(), String> {
    if value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }
    if is_dns_name(value) {
        return Ok(());
    }
    Err("Invalid DNS server".into())
}

pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty() || endpoint.len() > 300 || endpoint.chars().any(|c| c.is_whitespace()) {
        return Err("Invalid endpoint".into());
    }
    let port = if let Some(rest) = endpoint.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err("Invalid endpoint".into());
        };
        if host.parse::<Ipv6Addr>().is_err() {
            return Err("Invalid endpoint".into());
        }
        port
    } else {
        let Some((host, port)) = endpoint.rsplit_once(':') else {
            return Err("Invalid endpoint".into());
        };
        if host.parse::<Ipv4Addr>().is_err() && !is_dns_name(host) {
            return Err("Invalid endpoint".into());
        }
        port
    };
    let port: u16 = port.parse().map_err(|_| "Invalid endpoint".to_string())?;
    if port == 0 {
        return Err("Invalid endpoint".into());
    }
    Ok(())
}

pub fn validate_iface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("Invalid network interface name".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '(' | ')'))
    {
        return Err("Invalid network interface name".into());
    }
    Ok(())
}

pub fn validate_posix_install_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err("Application path must be absolute".into());
    }
    if path.chars().any(|c| {
        matches!(
            c,
            '\'' | '"'
                | '\\'
                | '\n'
                | '\r'
                | '$'
                | '`'
                | ';'
                | '|'
                | '&'
                | '<'
                | '>'
                | '('
                | ')'
                | '{'
                | '}'
                | '*'
                | '?'
                | '!'
                | '#'
                | '\t'
        )
    }) {
        return Err("Application path contains characters that cannot be installed safely".into());
    }
    Ok(())
}

pub fn validate_windows_install_path(path: &str) -> Result<(), String> {
    if path.len() < 3 || path.contains('\0') {
        return Err("Application path is not valid".into());
    }
    if path.chars().any(|c| {
        matches!(
            c,
            '\'' | '"' | '`' | '$' | ';' | '|' | '&' | '\n' | '\r' | '%' | '!' | '\t'
        )
    }) {
        return Err("Application path contains characters that cannot be installed safely".into());
    }
    Ok(())
}

/// Block native IPv6 when this tunnel cannot carry it and the config would
/// otherwise leave a path around a full tunnel. Split-tunnel configs that do
/// not claim the IPv4 default route keep native IPv6.
pub fn should_block_native_ipv6(has_ipv6_address: bool, allowed_ips: &[String]) -> bool {
    if has_ipv6_address {
        return false;
    }
    allowed_ips
        .iter()
        .any(|cidr| cidr == "0.0.0.0/0" || cidr == "0/0" || cidr.contains(':'))
}

pub fn is_ip_address(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok()
}

/// PowerShell and `route` receive this value unquoted. Only a decimal integer
/// is safe to interpolate.
pub fn parse_u32_token(value: &str) -> Result<u32, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 10
        || !value.chars().all(|c| c.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("Invalid interface index".into());
    }
    value
        .parse()
        .map_err(|_| "Invalid interface index".to_string())
}

/// Windows services run in session 0. An interactive `--helper` process does not.
pub fn is_windows_service_session(session_id: u32) -> bool {
    session_id == 0
}

pub fn is_windows_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    if sid.len() > 184 {
        return false;
    }
    let parts: Vec<&str> = rest.split('-').collect();
    !parts.is_empty()
        && parts.len() <= 15
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn is_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_addresses() {
        validate_ip_or_cidr("10.0.0.2").unwrap();
        validate_ip_or_cidr("10.0.0.2/32").unwrap();
        validate_ip_or_cidr("0.0.0.0/0").unwrap();
        validate_ip_or_cidr("fd00:1::2/128").unwrap();
        validate_dns("1.1.1.1").unwrap();
        validate_dns("dns.example.com").unwrap();
        validate_endpoint("vpn.example.com:51820").unwrap();
        validate_endpoint("203.0.113.10:51820").unwrap();
        validate_endpoint("[2001:db8::1]:51820").unwrap();
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert!(validate_ip_or_cidr("10.0.0.1/32; calc").is_err());
        assert!(validate_ip_or_cidr("10.0.0.1/32'").is_err());
        assert!(validate_dns("8.8.8.8; Remove-Item").is_err());
        assert!(validate_dns("$(whoami)").is_err());
        assert!(validate_endpoint("host:51820; reboot").is_err());
        assert!(validate_endpoint("host`n:1").is_err());
        assert!(validate_iface_name("tun0'; calc").is_err());
        assert!(validate_posix_install_path("/tmp/app'; rm -rf /").is_err());
        assert!(validate_windows_install_path("C:\\Program Files\\app.exe & calc").is_err());
    }

    #[test]
    fn ipv6_leak_protection_follows_the_tunnel() {
        let full = vec!["0.0.0.0/0".to_string()];
        let split = vec!["10.0.0.0/8".to_string()];
        let v6_only = vec!["fd00::/64".to_string()];
        assert!(should_block_native_ipv6(false, &full));
        assert!(should_block_native_ipv6(false, &v6_only));
        assert!(!should_block_native_ipv6(false, &split));
        assert!(!should_block_native_ipv6(true, &full));
    }

    #[test]
    fn interface_index_is_a_single_integer() {
        assert_eq!(parse_u32_token("12").unwrap(), 12);
        assert!(parse_u32_token("12\nRemove-Item C:\\").is_err());
        assert!(parse_u32_token("12; calc").is_err());
        assert!(parse_u32_token("").is_err());
        assert!(parse_u32_token("012").is_err());
        assert!(is_ip_address("203.0.113.1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(!is_ip_address("203.0.113.1; reboot"));
        assert!(!is_ip_address("$(reboot)"));
        assert!(is_windows_service_session(0));
        assert!(!is_windows_service_session(1));
    }

    #[test]
    fn sid_shape() {
        assert!(is_windows_sid("S-1-5-21-1-2-3-1001"));
        assert!(!is_windows_sid("S-1-5-21-1;calc"));
        assert!(!is_windows_sid("Everyone"));
        assert!(!is_windows_sid(""));
    }
}
