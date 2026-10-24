use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(target_os = "macos")]
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "macos")]
use std::ffi::CStr;
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "macos")]
use tokio::net::UnixListener;

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tokio::time::interval;

const MAX_PACKET: usize = 65536;

#[cfg(target_os = "macos")]
pub const SOCKET_PATH: &str = "/var/run/com.wedima.vpn.wg.helper.sock";
#[cfg(target_os = "windows")]
pub const PIPE_NAME: &str = r"\\.\pipe\com.wedima.vpn.wg.helper";

#[cfg(target_os = "macos")]
pub const UID_FILE: &str = "/Library/PrivilegedHelperTools/com.wedima.vpn.wg.helper.uid";
#[cfg(target_os = "macos")]
pub const VERSION_FILE: &str = "/Library/PrivilegedHelperTools/com.wedima.vpn.wg.helper.version";
#[cfg(target_os = "macos")]
pub const CLIENT_FILE: &str = "/Library/PrivilegedHelperTools/com.wedima.vpn.wg.helper.client";

pub const HELPER_LABEL: &str = "com.wedima.vpn.wg.helper";

const MAX_COMMAND_BYTES: usize = 400_000;
#[cfg(target_os = "macos")]
pub const HELPER_DEST: &str = "/Library/PrivilegedHelperTools/com.wedima.vpn.wg.helper";
#[cfg(target_os = "macos")]
pub const PLIST_DEST: &str = "/Library/LaunchDaemons/com.wedima.vpn.wg.helper.plist";

#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
#[cfg(target_os = "macos")]
const UTUN_OPT_IFNAME: libc::c_int = 2;
#[cfg(target_os = "macos")]
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

#[cfg(target_os = "macos")]
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn disable_ipv6() {
    for svc in network_services() {
        let _ = std::process::Command::new("networksetup")
            .args(["-setv6off", &svc])
            .status();
    }
}

#[cfg(target_os = "macos")]
fn enable_ipv6() {
    for svc in network_services() {
        let _ = std::process::Command::new("networksetup")
            .args(["-setv6automatic", &svc])
            .status();
    }
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn setup_dns(dns: &[String]) {
    if dns.is_empty() {
        return;
    }
    for svc in network_services() {
        let mut args = vec!["-setdnsservers".to_string(), svc];
        args.extend(dns.iter().cloned());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = std::process::Command::new("networksetup")
            .args(&arg_refs)
            .status();
    }
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "windows")]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(target_os = "windows")]
pub fn run_as_service() -> Result<(), windows_service::Error> {
    service_dispatcher::start(HELPER_LABEL, ffi_service_main)
}

#[cfg(target_os = "windows")]
fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(HELPER_LABEL, event_handler).expect("register service control handler");

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).expect("set service status");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        tokio::select! {
            _ = daemon_loop() => {},
            _ = async {
                while shutdown_rx.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => {},
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).expect("set service status stopped");
}

pub fn run_daemon() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(daemon_loop());
}

#[cfg(target_os = "macos")]
struct HelperGate {
    uid: u32,
    client_path: std::path::PathBuf,
    team_id: Option<String>,
}

#[cfg(target_os = "macos")]
impl HelperGate {
    fn load() -> Result<Self, String> {
        let uid: u32 = std::fs::read_to_string(UID_FILE)
            .map_err(|_| "helper identity file is missing".to_string())?
            .trim()
            .parse()
            .map_err(|_| "helper identity file is invalid".to_string())?;
        let client_path = std::fs::read_to_string(CLIENT_FILE)
            .map_err(|_| "helper client path is missing".to_string())?;
        let client_path = std::path::PathBuf::from(client_path.trim_end_matches(['\n', '\r']));
        let team_id = team_id_of(&client_path);
        Ok(Self {
            uid,
            client_path,
            team_id,
        })
    }

    fn allows(&self, stream: &tokio::net::UnixStream) -> bool {
        use std::os::fd::AsRawFd;
        let Ok(cred) = stream.peer_cred() else {
            return false;
        };
        if cred.uid != self.uid {
            return false;
        }
        let Ok(peer) = peer_executable(stream.as_raw_fd()) else {
            return false;
        };
        if let Some(expected) = &self.team_id {
            return team_id_of(&peer).as_ref() == Some(expected);
        }
        paths_equal(&peer, &self.client_path)
    }
}

#[cfg(target_os = "macos")]
fn peer_executable(fd: i32) -> Result<std::path::PathBuf, ()> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            0, // SOL_LOCAL
            2, // LOCAL_PEERPID
            &mut pid as *mut libc::pid_t as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(());
    }
    let mut buf = [0i8; 4096];
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr(), buf.len() as u32) };
    if n <= 0 {
        return Err(());
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize) };
    let path = String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string();
    Ok(std::path::PathBuf::from(path))
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_char, buffersize: u32) -> i32;
}

#[cfg(target_os = "macos")]
fn team_id_of(path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("codesign")
        .args(["-dv", "--verbose=4"])
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stderr);
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("TeamIdentifier=") else {
            continue;
        };
        let team = rest.trim();
        if !team.is_empty() && team != "not set" {
            return Some(team.to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn paths_equal(left: &std::path::Path, right: &std::path::Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
}

#[cfg(target_os = "macos")]
async fn daemon_loop() {
    let gate = match HelperGate::load() {
        Ok(gate) => gate,
        Err(err) => {
            eprintln!("helper refused to start: {err}");
            std::process::exit(1);
        }
    };

    let _ = std::fs::remove_file(SOCKET_PATH);
    let old_mask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(SOCKET_PATH).expect("bind helper socket");
    unsafe { libc::umask(old_mask) };

    use std::os::unix::fs::{chown, PermissionsExt};
    if chown(SOCKET_PATH, Some(gate.uid), None).is_err()
        || std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600)).is_err()
    {
        eprintln!("helper could not restrict its socket");
        std::process::exit(1);
    }

    let bytes_tx = Arc::new(AtomicU64::new(0));
    let bytes_rx = Arc::new(AtomicU64::new(0));
    let gate = Arc::new(gate);

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            if !gate.allows(&stream) {
                eprintln!("helper rejected a connection");
                continue;
            }
            let btx = Arc::clone(&bytes_tx);
            let brx = Arc::clone(&bytes_rx);
            tokio::spawn(async move {
                let (reader, writer) = stream.into_split();
                handle_client(BufReader::new(reader), writer, btx, brx).await;
            });
        }
    }
}

#[cfg(target_os = "windows")]
fn create_restricted_pipe(pipe_name: &str, first: bool) -> Result<NamedPipeServer, String> {
    use std::os::windows::ffi::OsStrExt;
    let wide_name: Vec<u16> = std::ffi::OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let sid = read_reg_sz("AllowedUserSid").ok_or("helper user is not registered")?;
    if !crate::validate::is_windows_sid(&sid) {
        return Err("helper user registration is invalid".into());
    }
    let sddl = format!("D:(A;;GA;;;SY)(A;;GRGW;;;{sid})");
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd_ptr: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut sa: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };

    unsafe {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            1,
            &mut sd_ptr,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err("security descriptor failed".into());
        }

        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = sd_ptr;
        sa.bInheritHandle = 0;

        let mut access = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            access |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }

        let handle = CreateNamedPipeW(
            wide_name.as_ptr(),
            access,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            255,   // max instances
            65536, // out buffer
            65536, // in buffer
            0,     // default timeout
            &sa,
        );

        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            LocalFree(sd_ptr as windows_sys::Win32::Foundation::HLOCAL);
            return Err(format!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error()));
        }
        LocalFree(sd_ptr as windows_sys::Win32::Foundation::HLOCAL);

        use std::os::windows::io::FromRawHandle;
        Ok(NamedPipeServer::from_raw_handle(handle as *mut _).map_err(|e| e.to_string())?)
    }
}

#[cfg(target_os = "windows")]
async fn daemon_loop() {
    let bytes_tx = Arc::new(AtomicU64::new(0));
    let bytes_rx = Arc::new(AtomicU64::new(0));
    let mut first = true;

    loop {
        let server = match create_restricted_pipe(PIPE_NAME, first) {
            Ok(s) => s,
            Err(_e) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        first = false;

        if server.connect().await.is_ok() {
            use std::os::windows::io::AsRawHandle;
            if ensure_pipe_peer_is_helper(server.as_raw_handle(), false).is_err() {
                eprintln!("helper rejected a connection");
                continue;
            }
            let btx = Arc::clone(&bytes_tx);
            let brx = Arc::clone(&bytes_rx);
            tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(server);
                handle_client(BufReader::new(reader), writer, btx, brx).await;
            });
        }
    }
}

struct ActiveTunnel {
    iface: String,
    stop_tx: broadcast::Sender<()>,
    allowed_ips: Vec<String>,
    dns: Vec<String>,
    ipv6_kill_switched: bool,
}

fn active_tunnel() -> &'static std::sync::Mutex<Option<ActiveTunnel>> {
    static ACTIVE: std::sync::OnceLock<std::sync::Mutex<Option<ActiveTunnel>>> =
        std::sync::OnceLock::new();
    ACTIVE.get_or_init(|| std::sync::Mutex::new(None))
}

fn teardown_active(tunnel: ActiveTunnel) {
    let _ = tunnel.stop_tx.send(());
    std::thread::sleep(Duration::from_millis(200));
    #[cfg(target_os = "macos")]
    teardown_routing(
        &tunnel.iface,
        &tunnel.allowed_ips,
        &tunnel.dns,
        tunnel.ipv6_kill_switched,
    );
    #[cfg(target_os = "windows")]
    {
        let _ = crate::wireguard::remove_routes(&tunnel.iface, &tunnel.allowed_ips, &tunnel.dns);
    }
}

fn take_and_teardown() {
    if let Ok(mut guard) = active_tunnel().lock() {
        if let Some(tunnel) = guard.take() {
            teardown_active(tunnel);
        }
    }
}

async fn read_limited_line<R>(reader: &mut R) -> Result<String, String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|e| e.to_string())?;
        if available.is_empty() {
            break;
        }
        if let Some(pos) = available.iter().position(|byte| *byte == b'\n') {
            if buf.len() + pos > MAX_COMMAND_BYTES {
                return Err("command too large".into());
            }
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }
        if buf.len() + available.len() > MAX_COMMAND_BYTES {
            return Err("command too large".into());
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
    }
    if buf.is_empty() {
        return Err("eof".into());
    }
    String::from_utf8(buf).map_err(|_| "invalid command".to_string())
}

async fn handle_client<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let line = match read_limited_line(&mut reader).await {
        Ok(line) => line,
        Err(_) => return,
    };

    let cmd = line.trim();
    if cmd == "STATS" {
        let tx = bytes_tx.load(Ordering::Relaxed);
        let rx = bytes_rx.load(Ordering::Relaxed);
        let _ = writer.write_all(format!("{} {}\n", tx, rx).as_bytes()).await;
        return;
    }

    if cmd == "SHUTDOWN" {
        take_and_teardown();
        std::process::exit(0);
    }

    if !cmd.starts_with("START ") {
        let _ = writer.write_all(b"ERROR invalid command\n").await;
        return;
    }

    let config_b64 = cmd[6..].to_string();
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
            if let Ok(mut guard) = active_tunnel().lock() {
                if let Some(previous) = guard.take() {
                    teardown_active(previous);
                }
                *guard = Some(ActiveTunnel {
                    iface,
                    stop_tx,
                    allowed_ips,
                    dns,
                    ipv6_kill_switched: ipv6_ks,
                });
            }
            let _ = read_limited_line(&mut reader).await;
            take_and_teardown();
            let _ = writer.write_all(b"DISCONNECTED\n").await;
        }
        Err(e) => {
            let _ = writer
                .write_all(format!("ERROR {}\n", e).as_bytes())
                .await;
        }
    }
}

async fn run_tunnel<W>(
    config_str: String,
    writer: &mut W,
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
> 
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let config = crate::wg_config::parse(&config_str)?;
    let peer = config.peers.first().ok_or("No [Peer] in config")?;

    let endpoint_str = peer.endpoint.as_deref().ok_or("Peer has no Endpoint")?;
    let endpoint: SocketAddr = endpoint_str
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .find(|a| a.is_ipv4())
        .ok_or("No IPv4 endpoint")?;

    let peer_ip = endpoint.ip().to_string();

    #[cfg(target_os = "macos")]
    let (tun_fd, iface) = create_utun_fd()?;
    #[cfg(target_os = "windows")]
    let (device, iface) = {
        let mut cfg = tun2::Configuration::default();
        let wintun_path = crate::wg_tunnel::wintun_dll_path();
        cfg.platform_config(|p| {
            p.wintun_file(&wintun_path);
        });
        let device = tun2::create_as_async(&cfg)
            .map_err(|e| format!("Failed to create TUN device: {}", e))?;
        use tun2::AbstractDevice;
        let name = device.tun_name().map_err(|e: tun2::Error| e.to_string())?.to_string();
        (device, name)
    };

    let (iface_addr, prefix_len) = config
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
    #[cfg(target_os = "windows")]
    let _ = has_ipv6_tunnel;

    #[cfg(target_os = "macos")]
    {
        configure_interface(
            &iface,
            &iface_addr,
            config.interface.mtu,
            iface_addr6.as_ref().map(|(a, p)| (a.as_str(), *p)),
        );
    }
    
#[cfg(target_os = "macos")]
    let ipv6_ks = setup_routing(&iface, &peer_ip, &peer.allowed_ips, has_ipv6_tunnel);
    #[cfg(target_os = "macos")]
    setup_dns(&config.interface.dns);
    #[cfg(target_os = "windows")]
    let ipv6_ks = false;
    #[cfg(target_os = "windows")]
    {
        use crate::wireguard::{IfaceConfig, setup_routes};
        let iface_cfg = IfaceConfig {
            addr: &iface_addr,
            prefix_len,
            addr6: iface_addr6.as_ref().map(|(a, p)| (a.as_str(), *p)),
            mtu: config.interface.mtu,
        };
        setup_routes(&iface, &iface_cfg, &peer.allowed_ips, &config.interface.dns, &peer_ip)?;
    }

    #[cfg(target_os = "macos")]
    let async_fd = {
        let owned_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        Arc::new(
            AsyncFd::new(owned_fd).map_err(|e| format!("AsyncFd: {}", e))?,
        )
    };
    #[cfg(target_os = "windows")]
    let (tun_reader, tun_writer) = tokio::io::split(device);

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

    #[cfg(target_os = "macos")]
    {
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
    }
    #[cfg(target_os = "windows")]
    {
        {
            let u = Arc::clone(&udp);
            let t = Arc::clone(&tunn);
            let btx = Arc::clone(&bytes_tx);
            let mut rx = stop_tx.subscribe();
            tokio::spawn(async move {
                crate::wg_tunnel::task_tun_to_udp(tun_reader, u, t, btx, &mut rx).await;
            });
        }
        {
            let u = Arc::clone(&udp);
            let t = Arc::clone(&tunn);
            let brx = Arc::clone(&bytes_rx);
            let mut rx = stop_tx.subscribe();
            tokio::spawn(async move {
                crate::wg_tunnel::task_udp_to_tun(tun_writer, u, t, brx, &mut rx).await;
            });
        }
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
pub fn is_installed() -> bool {
    std::path::Path::new(HELPER_DEST).exists() && std::path::Path::new(PLIST_DEST).exists()
}

#[cfg(target_os = "macos")]
pub fn helper_is_current(_current_exe: &str) -> bool {
    if !is_installed() {
        return false;
    }
    std::fs::read_to_string(VERSION_FILE)
        .map(|version| version.trim() == env!("CARGO_PKG_VERSION"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
pub fn helper_is_current(_current_exe: &str) -> bool {
    is_installed()
        && read_reg_sz("HelperVersion").as_deref() == Some(env!("CARGO_PKG_VERSION"))
}

#[cfg(target_os = "windows")]
pub fn is_installed() -> bool {
    let out = std::process::Command::new("sc")
        .args(["query", HELPER_LABEL])
        .output();
    
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            // Check if service exists AND is running
            o.status.success() && s.contains("STATE") && s.contains("RUNNING")
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
pub fn install(current_exe: &str) -> Result<(), String> {
    crate::validate::validate_posix_install_path(current_exe)?;
    if !std::path::Path::new(current_exe).is_file() {
        return Err("Application binary was not found.".into());
    }
    let uid = unsafe { libc::getuid() };
    let version = env!("CARGO_PKG_VERSION");
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
         chown root:wheel '{dest}' && \
         chmod 755 '{dest}' && \
         printf '%s' '{plist}' > '{plist_dest}' && \
         chmod 644 '{plist_dest}' && \
         printf '%s\n' '{uid}' > '{uid_file}' && \
         printf '%s\n' '{version}' > '{version_file}' && \
         printf '%s\n' '{exe}' > '{client_file}' && \
         chmod 644 '{uid_file}' '{version_file}' '{client_file}' && \
         touch /var/log/wedima-vpn-wg-helper.log && \
         chmod 600 /var/log/wedima-vpn-wg-helper.log && \
         launchctl unload '{plist_dest}' 2>/dev/null; \
         launchctl load -w '{plist_dest}'",
        exe = current_exe,
        dest = HELPER_DEST,
        plist = plist_escaped,
        plist_dest = PLIST_DEST,
        uid = uid,
        version = version,
        uid_file = UID_FILE,
        version_file = VERSION_FILE,
        client_file = CLIENT_FILE,
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

#[cfg(target_os = "windows")]
pub fn install(current_exe: &str) -> Result<(), String> {
    crate::validate::validate_windows_install_path(current_exe)?;
    let sid = current_user_sid()?;
    let version = env!("CARGO_PKG_VERSION");
    let exe_ps = current_exe.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $label = '{label}'; \
         $exe = '{exe}'; \
         $sid = '{sid}'; \
         $version = '{version}'; \
         if (Get-Service -Name $label -ErrorAction SilentlyContinue) {{ \
             Stop-Service -Name $label -Force -ErrorAction SilentlyContinue; \
             & sc.exe delete $label | Out-Null; \
             Start-Sleep -Seconds 2; \
         }}; \
         New-Service -Name $label -BinaryPathName \"`\"$exe`\"\" -DisplayName 'Wedima VPN Helper' -StartupType Automatic | Out-Null; \
         & sc.exe description $label 'Privileged helper for Wedima VPN WireGuard tunnel.' | Out-Null; \
         New-Item -Path 'HKLM:\\Software\\Wedima\\VpnWg' -Force | Out-Null; \
         Set-ItemProperty -Path 'HKLM:\\Software\\Wedima\\VpnWg' -Name AllowedUserSid -Value $sid; \
         Set-ItemProperty -Path 'HKLM:\\Software\\Wedima\\VpnWg' -Name HelperVersion -Value $version; \
         Start-Service -Name $label",
        label = HELPER_LABEL,
        exe = exe_ps,
        sid = sid,
        version = version,
    );

    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = "powershell\0".encode_utf16().collect();
    let encoded = encode_powershell(&script);
    let params: Vec<u16> = format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}\0",
        encoded
    )
    .encode_utf16()
    .collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_HIDE as i32,
        )
    };

    if result as isize <= 32 {
        return Err("Failed to install service with administrator privileges.".to_string());
    }

    std::thread::sleep(Duration::from_secs(3));
    Ok(())
}

#[cfg(target_os = "windows")]
fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    B64.encode(bytes)
}

#[cfg(target_os = "windows")]
fn current_user_sid() -> Result<String, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("Could not read the current user.".into());
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(token);
            return Err("Could not read the current user.".into());
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            let _ = CloseHandle(token);
            return Err("Could not read the current user.".into());
        }
        let _ = CloseHandle(token);
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_str) == 0 || sid_str.is_null() {
            return Err("Could not read the current user.".into());
        }
        let mut len = 0usize;
        while *sid_str.add(len) != 0 {
            len += 1;
            if len > 200 {
                break;
            }
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
        let _ = LocalFree(sid_str as HLOCAL);
        if !crate::validate::is_windows_sid(&sid) {
            return Err("Could not read the current user.".into());
        }
        Ok(sid)
    }
}

#[cfg(target_os = "windows")]
fn read_reg_sz(value_name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let subkey: Vec<u16> = "Software\\Wedima\\VpnWg\0".encode_utf16().collect();
    let name: Vec<u16> = format!("{value_name}\0").encode_utf16().collect();
    let mut buf = [0u16; 256];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1);
    let text = String::from_utf16_lossy(&buf[..len.min(buf.len())]);
    let text = text.trim_end_matches('\0').trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(target_os = "windows")]
pub fn ensure_pipe_peer_is_helper(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    peer_is_server: bool,
) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let mut pid = 0u32;
        let ok = if peer_is_server {
            GetNamedPipeServerProcessId(pipe, &mut pid)
        } else {
            GetNamedPipeClientProcessId(pipe, &mut pid)
        };
        if ok == 0 || pid == 0 {
            return Err("Could not identify the helper process.".into());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err("Could not identify the helper process.".into());
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let queried = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut size);
        let _ = CloseHandle(process);
        if queried == 0 {
            return Err("Could not identify the helper process.".into());
        }
        let image = String::from_utf16_lossy(&buf[..size as usize]);
        let own = std::env::current_exe().map_err(|_| "Could not identify the helper process.".to_string())?;
        if normalize_windows_path(&image) != normalize_windows_path(&own.to_string_lossy()) {
            return Err("Refusing to use an unexpected helper process.".into());
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn normalize_windows_path(path: &str) -> String {
    path.trim_start_matches(r"\\?\").replace('/', "\\").to_ascii_lowercase()
}

pub async fn request_shutdown() {
    use tokio::io::AsyncWriteExt;
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut stream) = tokio::net::UnixStream::connect(SOCKET_PATH).await {
            let _ = stream.write_all(b"SHUTDOWN\n").await;
            let _ = stream.flush().await;
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;
        if let Ok(mut stream) =
            tokio::net::windows::named_pipe::ClientOptions::new().open(PIPE_NAME)
        {
            if ensure_pipe_peer_is_helper(stream.as_raw_handle(), true).is_ok() {
                let _ = stream.write_all(b"SHUTDOWN\n").await;
                let _ = stream.flush().await;
            }
        }
    }
}
