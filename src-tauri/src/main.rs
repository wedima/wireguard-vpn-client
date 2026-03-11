#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--helper") {
        #[cfg(target_os = "macos")]
        wedima_vpn_wg_lib::tunnel_daemon::run_daemon();
        return;
    }
    wedima_vpn_wg_lib::run();
}
