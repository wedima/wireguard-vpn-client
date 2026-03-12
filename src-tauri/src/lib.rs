mod commands;
mod crypto;
mod wg_config;
#[cfg(not(target_os = "macos"))]
mod wg_tunnel;
#[cfg(not(target_os = "macos"))]
mod wireguard;

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod tunnel_daemon;

use commands::AppState;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

#[cfg(target_os = "macos")]
use cocoa::{
    appkit::{NSApp, NSApplication},
    base::YES,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .manage(AppState::new())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let show_item = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit Wedima VPN WG", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &sep, &quit_item])?;

            let tray_icon = {
                let bytes = include_bytes!("../icons/32x32.png");
                let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
                    .expect("decode tray icon");
                let rgba = img.to_rgba8();
                let (w, h) = (img.width(), img.height());
                tauri::image::Image::new_owned(rgba.into_raw(), w, h)
            };

            TrayIconBuilder::new()
                .icon(tray_icon)
                .icon_as_template(true)
                .tooltip("Wedima VPN WG")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            if w.is_visible().unwrap_or(false) {
                                let _ = w.hide();
                            } else {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            #[cfg(target_os = "macos")]
            {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }

                unsafe {
                    // Keep Accessory policy, but still make the app active at launch.
                    NSApp().activateIgnoringOtherApps_(YES);
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::check_status,
            commands::detect_config_type,
            commands::import_config,
            commands::setup_connection_password,
            commands::connect,
            commands::disconnect,
            commands::reset_config,
            commands::get_stats,
            commands::uninstall_helper,
            commands::quit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running application");
}
