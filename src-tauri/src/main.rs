#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--version") {
        println!("wedima-vpn-wg {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.get(1).map(String::as_str) == Some("--helper") {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            wedima_vpn_wg_lib::tunnel_daemon::run_daemon();
            return;
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            eprintln!("--helper is only available on macOS and Windows");
            std::process::exit(1);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // SCM starts this same binary as a service. A normal launch fails here
        // and continues into the window. `--version` and `--helper` are handled
        // first so a smoke test never enters the service dispatcher.
        let _ = wedima_vpn_wg_lib::tunnel_daemon::run_as_service();
    }

    wedima_vpn_wg_lib::run();
}
