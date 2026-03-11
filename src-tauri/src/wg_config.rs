use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug, Clone)]
pub struct WgInterface {
    pub private_key: [u8; 32],
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u32,
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct WgPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct WgConfig {
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
    pub name: Option<String>,
}

fn decode_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(s.trim())
        .map_err(|e| format!("Invalid base64 key: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| "Key must be exactly 32 bytes".to_string())
}

pub fn parse(conf: &str) -> Result<WgConfig, String> {
    let mut section = "";

    let mut name: Option<String> = None;
    let mut priv_key: Option<[u8; 32]> = None;
    let mut iface_addrs: Vec<String> = vec![];
    let mut iface_dns: Vec<String> = vec![];
    let mut iface_mtu: u32 = 1420;
    let mut listen_port: Option<u16> = None;

    let mut peers: Vec<WgPeer> = vec![];
    let mut p_pub: Option<[u8; 32]> = None;
    let mut p_psk: Option<[u8; 32]> = None;
    let mut p_endpoint: Option<String> = None;
    let mut p_aips: Vec<String> = vec![];
    let mut p_ka: Option<u16> = None;
    let mut in_peer = false;

    let flush_peer = |in_peer: &mut bool,
                      p_pub: &mut Option<[u8; 32]>,
                      p_psk: &mut Option<[u8; 32]>,
                      p_endpoint: &mut Option<String>,
                      p_aips: &mut Vec<String>,
                      p_ka: &mut Option<u16>,
                      peers: &mut Vec<WgPeer>|
     -> Result<(), String> {
        if *in_peer {
            peers.push(WgPeer {
                public_key: p_pub.take().ok_or("Peer missing PublicKey")?,
                preshared_key: p_psk.take(),
                endpoint: p_endpoint.take(),
                allowed_ips: std::mem::take(p_aips),
                keepalive: p_ka.take(),
            });
            *in_peer = false;
        }
        Ok(())
    };

    for raw in conf.lines() {
        let line = raw.trim();
        if line.starts_with("# Client name:") {
            name = Some(line["# Client name:".len()..].trim().to_string());
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            flush_peer(
                &mut in_peer,
                &mut p_pub,
                &mut p_psk,
                &mut p_endpoint,
                &mut p_aips,
                &mut p_ka,
                &mut peers,
            )?;
            section = match line {
                "[Interface]" => "iface",
                "[Peer]" => {
                    in_peer = true;
                    "peer"
                }
                _ => "",
            };
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());

        match section {
            "iface" => match k {
                "PrivateKey" => priv_key = Some(decode_key(v)?),
                "Address" => iface_addrs.extend(v.split(',').map(|s| s.trim().to_string())),
                "DNS" => iface_dns.extend(v.split(',').map(|s| s.trim().to_string())),
                "MTU" => iface_mtu = v.parse().unwrap_or(1420),
                "ListenPort" => listen_port = v.parse().ok(),
                _ => {}
            },
            "peer" => match k {
                "PublicKey" => p_pub = Some(decode_key(v)?),
                "PresharedKey" => p_psk = Some(decode_key(v)?),
                "Endpoint" => p_endpoint = Some(v.to_string()),
                "AllowedIPs" => p_aips.extend(v.split(',').map(|s| s.trim().to_string())),
                "PersistentKeepalive" => p_ka = v.parse().ok(),
                _ => {}
            },
            _ => {}
        }
    }

    flush_peer(
        &mut in_peer,
        &mut p_pub,
        &mut p_psk,
        &mut p_endpoint,
        &mut p_aips,
        &mut p_ka,
        &mut peers,
    )?;

    if peers.is_empty() {
        return Err("WireGuard config has no [Peer] section".into());
    }

    Ok(WgConfig {
        interface: WgInterface {
            private_key: priv_key.ok_or("Interface missing PrivateKey")?,
            addresses: iface_addrs,
            dns: iface_dns,
            mtu: iface_mtu,
            listen_port,
        },
        peers,
        name,
    })
}

pub fn cidr_to_netmask(prefix_len: u8) -> String {
    if prefix_len == 0 {
        return "0.0.0.0".to_string();
    }
    let mask: u32 = !0u32 << (32 - prefix_len);
    let b = mask.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}
