#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::io::unix::AsyncFd;
use tokio::net::{UnixListener, UnixStream, UdpSocket};
use tokio::sync::{broadcast, Mutex};
use tokio::time::interval;

const MAX_PACKET: usize = 65536;
pub const SOCKET_PATH: &str = "/var/run/com.wedima.vpn.wg.helper.sock";
pub const HELPER_LABEL: &str = "com.wedima.vpn.wg.helper";
pub const HELPER_DEST: &str = "/Library/PrivilegedHelperTools/com.wedima.vpn.wg.helper";
pub const PLIST_DEST: &str = "/Library/LaunchDaemons/com.wedima.vpn.wg.helper.plist";

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const UTUN_OPT_IFNAME: libc::c_int = 2;
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

fn create_utun_fd() -> Result<(i32, String), String> {
    unsafe {
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(format!("socket: {}", std::io::Error::last_os_error()));
        }
        let mut info = CtlInfo { ctl_id: 0, ctl_name: [0u8; 96] };
        let n = UTUN_CONTROL_NAME;
        info.ctl_name[..n.len() - 1].copy_from_slice(&n[..n.len() - 1]);

        if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _ as *mut libc::c_void) < 0 {
            libc::close(fd);
            return Err(format!("ctliocginfo: {}", std::io::Error::last_os_error()));
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
            return Err(format!("connect: {}", std::io::Error::last_os_error()));
        }
        let mut buf = [0u8; 64];
        let mut len: libc::socklen_t = 64;
        if libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        ) < 0
        {
            libc::close(fd);
            return Err(format!("getsockopt: {}", std::io::Error::last_os_error()));
        }
        let name = CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
            .to_string_lossy()
            .into_owned();
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        Ok((fd, name))
    }
}

fn configure_interface(iface: &str, addr4: &str, mtu: u32, addr6: Option<(&str, u8)>) {
    let _ = std::process::Command::new("ifconfig")
        .args([iface, "inet", addr4, addr4, "up"])
        .status();
    let _ = std::process::Command::new("ifconfig")
        .args([iface, "mtu", &mtu.to_string()])
        .status();
    if let Some((a6, plen)) = addr6 {
        let _ = std::process::Command::new("ifconfig")
            .args([iface, "inet6", a6, "prefixlen", &plen.to_string(), "up"])
            .status();
    }
}

fn default_gateway() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.trim().starts_with("gateway:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_string)
}

fn default_gateway_v6() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.trim().starts_with("gateway:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_string)
}

fn network_services() -> Vec<String> {
    let out = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: vec![],
            stderr: vec![],
        });
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.contains('*') && !l.trim().is_empty() && !l.contains("network services"))
        .map(str::to_string)
        .collect()
}

fn disable_ipv6() {
    for svc in network_services() {
        let _ = std::process::Command::new("networksetup")
            .args(["-setv6off", &svc])
            .status();
    }
}

fn enable_ipv6() {
    for svc in network_services() {
        let _ = std::process::Command::new("networksetup")
            .args(["-setv6automatic", &svc])
            .status();
    }
}

fn setup_routing(iface: &str, peer_ip: &str, allowed_ips: &[String], has_ipv6_tunnel: bool) -> bool {
    if let Some(gw) = default_gateway() {
        let _ = std::process::Command::new("route")
            .args(["add", "-host", peer_ip, &gw])
            .status();
    }
    for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
        if cidr == "0.0.0.0/0" || cidr == "0/0" {
            let _ = std::process::Command::new("route")
                .args(["add", "-net", "0.0.0.0/1", "-interface", iface])
                .status();
            let _ = std::process::Command::new("route")
                .args(["add", "-net", "128.0.0.0/1", "-interface", iface])
                .status();
        } else {
            let _ = std::process::Command::new("route")
                .args(["add", "-net", cidr, "-interface", iface])
                .status();
        }
    }

    let ipv6_allowed: Vec<&String> = allowed_ips.iter().filter(|c| c.contains(':')).collect();
    let mut ipv6_kill_switched = false;

    if !ipv6_allowed.is_empty() {
        if has_ipv6_tunnel {
            if let Some(gw6) = default_gateway_v6() {
                let _ = std::process::Command::new("route")
                    .args(["add", "-inet6", "-host", peer_ip, &gw6])
                    .status();
            }
            for cidr in &ipv6_allowed {
                if *cidr == "::/0" {
                    let _ = std::process::Command::new("route")
                        .args(["add", "-inet6", "-net", "::/1", "-interface", iface])
                        .status();
                    let _ = std::process::Command::new("route")
                        .args(["add", "-inet6", "-net", "8000::/1", "-interface", iface])
                        .status();
                } else {
                    let _ = std::process::Command::new("route")
                        .args(["add", "-inet6", "-net", cidr, "-interface", iface])
                        .status();
                }
            }
        } else {
            disable_ipv6();
            ipv6_kill_switched = true;
        }
    }

    ipv6_kill_switched
}

fn setup_dns(dns: &[String]) {
    let all: Vec<&str> = dns.iter().map(|s| s.as_str()).collect();
    if all.is_empty() {
        return;
    }
    let list = all.join(" ");
    for svc in network_services() {
        let _ = std::process::Command::new("networksetup")
            .args(["-setdnsservers", &svc, &list])
            .status();
    }
}

fn teardown_routing(iface: &str, allowed_ips: &[String], dns: &[String], ipv6_kill_switched: bool) {
    for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
        if cidr == "0.0.0.0/0" || cidr == "0/0" {
            let _ = std::process::Command::new("route")
                .args(["delete", "-net", "0.0.0.0/1", "-interface", iface])
                .status();
            let _ = std::process::Command::new("route")
                .args(["delete", "-net", "128.0.0.0/1", "-interface", iface])
                .status();
        } else {
            let _ = std::process::Command::new("route")
                .args(["delete", "-net", cidr, "-interface", iface])
                .status();
        }
    }
    for cidr in allowed_ips.iter().filter(|c| c.contains(':')) {
        if *cidr == "::/0" {
            let _ = std::process::Command::new("route")
                .args(["delete", "-inet6", "-net", "::/1", "-interface", iface])
                .status();
            let _ = std::process::Command::new("route")
                .args(["delete", "-inet6", "-net", "8000::/1", "-interface", iface])
                .status();
        } else {
            let _ = std::process::Command::new("route")
                .args(["delete", "-inet6", "-net", cidr, "-interface", iface])
                .status();
        }
    }
    if !dns.is_empty() {
        for svc in network_services() {
            let _ = std::process::Command::new("networksetup")
                .args(["-setdnsservers", &svc, "Empty"])
                .status();
        }
    }
    if ipv6_kill_switched {
        enable_ipv6();
    }
}

pub fn run_daemon() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(daemon_loop());
}

async fn daemon_loop() {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).expect("bind helper socket");

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        SOCKET_PATH,
        std::fs::Permissions::from_mode(0o777),
    );

    let bytes_tx = Arc::new(AtomicU64::new(0));
    let bytes_rx = Arc::new(AtomicU64::new(0));

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let btx = Arc::clone(&bytes_tx);
            let brx = Arc::clone(&bytes_rx);
            tokio::spawn(async move {
                handle_client(stream, btx, brx).await;
            });
        }
    }
}

async fn handle_client(stream: UnixStream, bytes_tx: Arc<AtomicU64>, bytes_rx: Arc<AtomicU64>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut line = String::new();
    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }

    if line.trim() == "STATS" {
        let tx = bytes_tx.load(Ordering::Relaxed);
        let rx = bytes_rx.load(Ordering::Relaxed);
        let _ = writer.write_all(format!("{} {}\n", tx, rx).as_bytes()).await;
        return;
    }

    if !line.starts_with("START ") {
        let _ = writer.write_all(b"ERROR invalid command\n").await;
        return;
    }

    let config_b64 = line.trim()[6..].to_string();
    let config_bytes = match B64.decode(&config_b64) {
        Ok(b) => b,
        Err(e) => {
            let _ = writer
                .write_all(format!("ERROR base64: {}\n", e).as_bytes())
                .await;
            return;
        }
    };
    let config_str = match String::from_utf8(config_bytes) {
        Ok(s) => s,
        Err(e) => {
            let _ = writer
                .write_all(format!("ERROR utf8: {}\n", e).as_bytes())
                .await;
            return;
        }
    };

    bytes_tx.store(0, Ordering::Relaxed);
    bytes_rx.store(0, Ordering::Relaxed);

    match run_tunnel(config_str, &mut writer, bytes_tx, bytes_rx).await {
        Ok((iface, stop_tx, allowed_ips, dns, ipv6_ks)) => {
            let mut stop_line = String::new();
            reader.read_line(&mut stop_line).await.ok();
            let _ = stop_tx.send(());
            tokio::time::sleep(Duration::from_millis(200)).await;
            teardown_routing(&iface, &allowed_ips, &dns, ipv6_ks);
            let _ = writer.write_all(b"DISCONNECTED\n").await;
        }
        Err(e) => {
            let _ = writer
                .write_all(format!("ERROR {}\n", e).as_bytes())
                .await;
        }
    }
}

async fn run_tunnel(
    config_str: String,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
) -> Result<
    (
        String,
        broadcast::Sender<()>,
        Vec<String>,
        Vec<String>,
        bool,
    ),
    String,
> {
    let config = crate::wg_config::parse(&config_str)?;
    let peer = config.peers.first().ok_or("No [Peer] in config")?;

    let endpoint_str = peer.endpoint.as_deref().ok_or("Peer has no Endpoint")?;
    let endpoint: SocketAddr = endpoint_str
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .find(|a| a.is_ipv4())
        .ok_or("No IPv4 endpoint")?;

    let peer_ip = endpoint.ip().to_string();

    let (tun_fd, iface) = create_utun_fd()?;

    let (iface_addr, _prefix_len) = config
        .interface
        .addresses
        .iter()
        .find(|a| !a.contains(':'))
        .map(|cidr| {
            let (a, p) = cidr.split_once('/').unwrap_or((cidr, "24"));
            (a.to_string(), p.parse::<u8>().unwrap_or(24))
        })
        .ok_or("No IPv4 address in [Interface]")?;

    let iface_addr6 = config.interface.addresses.iter().find(|a| a.contains(':')).map(|cidr| {
        let (a, p) = cidr.split_once('/').unwrap_or((cidr, "128"));
        (a.to_string(), p.parse::<u8>().unwrap_or(128))
    });

    let has_ipv6_tunnel = iface_addr6.is_some();

    configure_interface(
        &iface,
        &iface_addr,
        config.interface.mtu,
        iface_addr6.as_ref().map(|(a, p)| (a.as_str(), *p)),
    );
    let ipv6_ks = setup_routing(&iface, &peer_ip, &peer.allowed_ips, has_ipv6_tunnel);
    setup_dns(&config.interface.dns);

    let owned_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    let async_fd = Arc::new(
        AsyncFd::new(owned_fd).map_err(|e| format!("AsyncFd: {}", e))?,
    );

    let private_key = StaticSecret::from(config.interface.private_key);
    let peer_pub = PublicKey::from(peer.public_key);
    let tunn = Tunn::new(
        private_key,
        peer_pub,
        peer.preshared_key,
        peer.keepalive,
        0,
        None,
    )
    .map_err(|e| e.to_string())?;

    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("UDP bind: {}", e))?;
    udp.connect(endpoint).await.map_err(|e| format!("UDP connect: {}", e))?;
    let udp = Arc::new(udp);
    let tunn = Arc::new(Mutex::new(tunn));
    let (stop_tx, _) = broadcast::channel::<()>(4);

    {
        let tun = Arc::clone(&async_fd);
        let u = Arc::clone(&udp);
        let t = Arc::clone(&tunn);
        let btx = Arc::clone(&bytes_tx);
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move { task_tun_to_udp(tun, u, t, btx, &mut rx).await });
    }
    {
        let tun = Arc::clone(&async_fd);
        let u = Arc::clone(&udp);
        let t = Arc::clone(&tunn);
        let brx = Arc::clone(&bytes_rx);
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move { task_udp_to_tun(tun, u, t, brx, &mut rx).await });
    }
    {
        let u = Arc::clone(&udp);
        let t = Arc::clone(&tunn);
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move { task_timers(u, t, &mut rx).await });
    }

    writer
        .write_all(format!("READY {}\n", iface).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.flush().await.ok();

    Ok((
        iface,
        stop_tx,
        peer.allowed_ips.clone(),
        config.interface.dns.clone(),
        ipv6_ks,
    ))
}

async fn tun_read(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

fn tun_write_sync(fd: &OwnedFd, buf: &[u8]) -> std::io::Result<()> {
    let n = unsafe {
        libc::write(fd.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len())
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

async fn task_tun_to_udp(
    tun: Arc<AsyncFd<OwnedFd>>,
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
            r = tun_read(&tun, &mut pkt) => {
                let n = match r { Ok(0) | Err(_) => break, Ok(n) => n };
                if n <= 4 { continue; }
                let payload_len = n - 4;
                let mut g = tunn.lock().await;
                match g.encapsulate(&pkt[4..n], &mut enc) {
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

async fn task_udp_to_tun(
    tun: Arc<AsyncFd<OwnedFd>>,
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
                            let hdr = [0u8, 0, 0, libc::AF_INET as u8];
                            let mut buf = Vec::with_capacity(4 + data.len());
                            buf.extend_from_slice(&hdr);
                            buf.extend_from_slice(data);
                            bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
                            let _ = tun_write_sync(tun.get_ref(), &buf);
                            break;
                        }
                        TunnResult::WriteToTunnelV6(data, _) => {
                            let hdr = [0u8, 0, 0, libc::AF_INET6 as u8];
                            let mut buf = Vec::with_capacity(4 + data.len());
                            buf.extend_from_slice(&hdr);
                            buf.extend_from_slice(data);
                            bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
                            let _ = tun_write_sync(tun.get_ref(), &buf);
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

pub fn is_installed() -> bool {
    std::path::Path::new(HELPER_DEST).exists()
        && std::path::Path::new(PLIST_DEST).exists()
}

pub fn install(current_exe: &str) -> Result<(), String> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{dest}</string>
        <string>--helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/wedima-vpn-wg-helper.log</string>
</dict>
</plist>"#,
        label = HELPER_LABEL,
        dest = HELPER_DEST,
    );

    let plist_escaped = plist.replace('\'', "'\\''");
    let script = format!(
        "cp '{exe}' '{dest}' && \
         chmod 755 '{dest}' && \
         printf '%s' '{plist}' > '{plist_dest}' && \
         chmod 644 '{plist_dest}' && \
         launchctl unload '{plist_dest}' 2>/dev/null; \
         launchctl load -w '{plist_dest}'",
        exe = current_exe,
        dest = HELPER_DEST,
        plist = plist_escaped,
        plist_dest = PLIST_DEST,
    );

    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges",
        script.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let out = std::process::Command::new("osascript")
        .args(["-e", &apple_script])
        .output()
        .map_err(|e| format!("osascript failed: {}", e))?;

    if out.status.success() {
        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    } else {
        Err(format!(
            "Helper installation failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}
