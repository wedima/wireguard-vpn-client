#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "windows")]
    {
        // Try to run as a service. If it fails (e.g. running as a normal app), continue.
        let _ = wedima_vpn_wg_lib::tunnel_daemon::run_as_service();
    }

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--helper") {
        wedima_vpn_wg_lib::tunnel_daemon::run_daemon();
        return;
    }
    wedima_vpn_wg_lib::run();
}
