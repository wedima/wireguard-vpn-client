use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tokio::time::interval;

use crate::wireguard::{self, IfaceConfig};

const MAX_PACKET: usize = 65536;

pub struct WgSession {
    stop_tx: broadcast::Sender<()>,
    pub interface_name: String,
    pub allowed_ips: Vec<String>,
    pub dns: Vec<String>,
    pub bytes_tx: Arc<AtomicU64>,
    pub bytes_rx: Arc<AtomicU64>,
    ipv6_blackhole: bool,
}

impl WgSession {
    pub async fn start(conf_str: &str) -> Result<Self, String> {
        let config = crate::wg_config::parse(conf_str)?;
        let peer = config.peers.first().ok_or("No [Peer] in config")?;

        let endpoint_str = peer
            .endpoint
            .as_deref()
            .ok_or("Peer has no Endpoint field")?;

        let endpoint: SocketAddr = endpoint_str
            .to_socket_addrs()
            .map_err(|e| format!("Cannot resolve '{}': {}", endpoint_str, e))?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| format!("No IPv4 address for '{}'", endpoint_str))?;

        let peer_endpoint_ip = endpoint.ip().to_string();

        let private_key = StaticSecret::from(config.interface.private_key);
        let peer_public_key = PublicKey::from(peer.public_key);

        let tunn = Tunn::new(
            private_key,
            peer_public_key,
            peer.preshared_key,
            peer.keepalive,
            0,
            None,
        );

        let (device, interface_name) = create_tun_device()?;

        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("UDP bind failed: {}", e))?;
        udp.connect(endpoint)
            .await
            .map_err(|e| format!("UDP connect failed: {}", e))?;
        let udp = Arc::new(udp);

        let tunn: Arc<Mutex<Tunn>> = Arc::new(Mutex::new(tunn));
        let (stop_tx, _) = broadcast::channel::<()>(4);

        let (iface_addr, prefix_len) =
            if let Some(addr_cidr) = config.interface.addresses.iter().find(|a| !a.contains(':')) {
                let (addr, prefix) = addr_cidr.split_once('/').unwrap_or((addr_cidr, "24"));
                let prefix_len: u8 = prefix.parse().unwrap_or(24);
                (addr.to_string(), prefix_len)
            } else {
                return Err("No IPv4 address in [Interface] section".to_string());
            };

        let iface_addr6 = config
            .interface
            .addresses
            .iter()
            .find(|a| a.contains(':'))
            .map(|cidr| {
                let (a, p) = cidr.split_once('/').unwrap_or((cidr, "128"));
                (a.to_string(), p.parse::<u8>().unwrap_or(128))
            });

        let iface_cfg = IfaceConfig {
            addr: &iface_addr,
            prefix_len,
            addr6: iface_addr6.as_ref().map(|(a, p)| (a.as_str(), *p)),
            mtu: config.interface.mtu,
        };

        let ipv6_blackhole =
            crate::validate::should_block_native_ipv6(iface_addr6.is_some(), &peer.allowed_ips);
        wireguard::setup_routes(
            &interface_name,
            &iface_cfg,
            &peer.allowed_ips,
            &config.interface.dns,
            &peer_endpoint_ip,
        )?;

        let (tun_reader, tun_writer) = tokio::io::split(device);

        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));

        {
            let udp = Arc::clone(&udp);
            let tunn = Arc::clone(&tunn);
            let btx = Arc::clone(&bytes_tx);
            let mut rx = stop_tx.subscribe();
            tokio::spawn(async move {
                task_tun_to_udp(tun_reader, udp, tunn, btx, &mut rx).await;
            });
        }
        {
            let udp = Arc::clone(&udp);
            let tunn = Arc::clone(&tunn);
            let brx = Arc::clone(&bytes_rx);
            let mut rx = stop_tx.subscribe();
            tokio::spawn(async move {
                task_udp_to_tun(tun_writer, udp, tunn, brx, &mut rx).await;
            });
        }
        {
            let udp = Arc::clone(&udp);
            let tunn = Arc::clone(&tunn);
            let mut rx = stop_tx.subscribe();
            tokio::spawn(async move {
                task_timers(udp, tunn, &mut rx).await;
            });
        }

        Ok(WgSession {
            stop_tx,
            interface_name,
            allowed_ips: peer.allowed_ips.clone(),
            dns: config.interface.dns.clone(),
            bytes_tx,
            bytes_rx,
            ipv6_blackhole,
        })
    }

    pub fn stop(self) -> Result<(), String> {
        let _ = self.stop_tx.send(());
        wireguard::remove_routes(
            &self.interface_name,
            &self.allowed_ips,
            &self.dns,
            self.ipv6_blackhole,
        )
    }
}

#[cfg(target_os = "windows")]
pub fn wintun_dll_path() -> std::path::PathBuf {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("wintun.dll"));
            candidates.push(dir.join("resources").join("wintun.dll"));
            candidates.push(dir.join("Resources").join("wintun.dll"));
        }
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| std::path::PathBuf::from("wintun.dll"))
}

fn create_tun_device() -> Result<(tun2::AsyncDevice, String), String> {
    #[cfg(target_os = "macos")]
    {
        macos_utun::create_utun_async()
    }

    #[cfg(not(target_os = "macos"))]
    {
        #[allow(unused_mut)]
        let mut cfg = tun2::Configuration::default();
        #[cfg(target_os = "windows")]
        {
            let wintun_path = wintun_dll_path();
            cfg.platform_config(|p| {
                p.wintun_file(&wintun_path);
            });
        }
        let device = tun2::create_as_async(&cfg)
            .map_err(|e| format!("Failed to create TUN device: {}", e))?;
        use tun2::AbstractDevice;
        let name = device
            .tun_name()
            .map_err(|e: tun2::Error| e.to_string())?
            .to_string();
        Ok((device, name))
    }
}

#[cfg(target_os = "macos")]
mod macos_utun {
    use std::ffi::CStr;

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    pub fn create_utun_async() -> Result<(tun2::AsyncDevice, String), String> {
        let (fd, name) = create_utun_fd()?;

        let mut cfg = tun2::Configuration::default();
        cfg.raw_fd(fd);
        cfg.platform_config(|p| {
            p.packet_information(true);
        });

        let device =
            tun2::create_as_async(&cfg).map_err(|e| format!("Failed to wrap utun fd: {}", e))?;

        Ok((device, name))
    }

    fn create_utun_fd() -> Result<(i32, String), String> {
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(format!(
                    "Failed to create utun socket: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0u8; 96],
            };
            let name_bytes = UTUN_CONTROL_NAME;
            info.ctl_name[..name_bytes.len() - 1]
                .copy_from_slice(&name_bytes[..name_bytes.len() - 1]);

            if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _ as *mut libc::c_void) < 0 {
                libc::close(fd);
                return Err(format!(
                    "ctliocginfo failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let addr = libc::sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };

            if libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(format!(
                    "utun connect failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut ifname_buf = [0u8; 64];
            let mut ifname_len: libc::socklen_t = 64;
            if libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            ) < 0
            {
                libc::close(fd);
                return Err(format!(
                    "getsockopt UTUN_OPT_IFNAME failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let iface_name = CStr::from_ptr(ifname_buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned();

            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

            Ok((fd, iface_name))
        }
    }
}

pub async fn task_tun_to_udp(
    mut reader: tokio::io::ReadHalf<tun2::AsyncDevice>,
    udp: Arc<UdpSocket>,
    tunn: Arc<Mutex<Tunn>>,
    bytes_tx: Arc<AtomicU64>,
    stop: &mut broadcast::Receiver<()>,
) {
    let mut pkt = vec![0u8; MAX_PACKET];
    let mut enc = vec![0u8; MAX_PACKET];

    loop {
        tokio::select! {
            biased;
            _ = stop.recv() => break,
            n = reader.read(&mut pkt) => {
                let n = match n { Ok(0) | Err(_) => break, Ok(n) => n };
                if n == 0 { continue; }
                let payload_len = n;
                let mut g = tunn.lock().await;
                match g.encapsulate(&pkt[..n], &mut enc) {
                    TunnResult::WriteToNetwork(data) => {
                        let data = data.to_vec();
                        drop(g);
                        let _ = udp.send(&data).await;
                        bytes_tx.fetch_add(payload_len as u64, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
    }
}

pub async fn task_udp_to_tun(
    mut writer: tokio::io::WriteHalf<tun2::AsyncDevice>,
    udp: Arc<UdpSocket>,
    tunn: Arc<Mutex<Tunn>>,
    bytes_rx: Arc<AtomicU64>,
    stop: &mut broadcast::Receiver<()>,
) {
    let mut pkt = vec![0u8; MAX_PACKET];
    let mut dec = vec![0u8; MAX_PACKET];

    loop {
        tokio::select! {
            biased;
            _ = stop.recv() => break,
            r = udp.recv_from(&mut pkt) => {
                let (n, src) = match r { Ok(v) => v, Err(_) => break };
                let src_ip: IpAddr = src.ip();
                let mut result = {
                    let mut g = tunn.lock().await;
                    g.decapsulate(Some(src_ip), &pkt[..n], &mut dec)
                };
                loop {
                    match result {
                        TunnResult::WriteToTunnelV4(data, _) => {
                            bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
                            let _ = writer.write_all(data).await;
                            break;
                        }
                        TunnResult::WriteToTunnelV6(data, _) => {
                            bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
                            let _ = writer.write_all(data).await;
                            break;
                        }
                        TunnResult::WriteToNetwork(data) => {
                            let data = data.to_vec();
                            let _ = udp.send(&data).await;
                            let mut g = tunn.lock().await;
                            result = g.decapsulate(None, &[], &mut dec);
                        }
                        _ => break,
                    }
                }
            }
        }
    }
}

async fn task_timers(
    udp: Arc<UdpSocket>,
    tunn: Arc<Mutex<Tunn>>,
    stop: &mut broadcast::Receiver<()>,
) {
    let mut tick = interval(Duration::from_millis(250));
    let mut buf = vec![0u8; MAX_PACKET];

    loop {
        tokio::select! {
            biased;
            _ = stop.recv() => break,
            _ = tick.tick() => {
                let mut g = tunn.lock().await;
                if let TunnResult::WriteToNetwork(data) = g.update_timers(&mut buf) {
                    let data = data.to_vec();
                    drop(g);
                    let _ = udp.send(&data).await;
                }
            }
        }
    }
}
