pub struct IfaceConfig<'a> {
    pub addr: &'a str,
    pub prefix_len: u8,
    pub mtu: u32,
}

pub fn setup_routes(
    interface: &str,
    iface_cfg: &IfaceConfig<'_>,
    allowed_ips: &[String],
    dns: &[String],
    peer_endpoint_ip: &str,
) -> Result<(), String> {
    platform::setup(interface, iface_cfg, allowed_ips, dns, peer_endpoint_ip)
}

pub fn remove_routes(
    interface: &str,
    allowed_ips: &[String],
    dns: &[String],
) -> Result<(), String> {
    platform::teardown(interface, allowed_ips, dns)
}

// ── macOS ────────────────────────────────────────────────────────────────────
#[cfg(target_os = "macos")]
mod platform {
    use super::IfaceConfig;
    use crate::wg_config::cidr_to_netmask;

    pub fn setup(
        interface: &str,
        iface_cfg: &IfaceConfig<'_>,
        allowed_ips: &[String],
        dns: &[String],
        peer_endpoint_ip: &str,
    ) -> Result<(), String> {
        let mut cmds: Vec<String> = vec![];

        let netmask = cidr_to_netmask(iface_cfg.prefix_len);
        cmds.push(format!(
            "ifconfig {} {} {} netmask {} mtu {} up",
            interface, iface_cfg.addr, iface_cfg.addr, netmask, iface_cfg.mtu
        ));

        if let Some(gw) = default_gateway() {
            cmds.push(format!("route add -host {} {}", peer_endpoint_ip, gw));
        }

        for cidr in allowed_ips {
            if cidr.contains(':') {
                continue;
            }
            if cidr == "0.0.0.0/0" || cidr == "0/0" {
                cmds.push(format!(
                    "route add -net 0.0.0.0/1 -interface {}",
                    interface
                ));
                cmds.push(format!(
                    "route add -net 128.0.0.0/1 -interface {}",
                    interface
                ));
            } else {
                cmds.push(format!("route add -net {} -interface {}", cidr, interface));
            }
        }

        if !dns.is_empty() {
            let v4: Vec<&str> = dns.iter().filter(|d| !d.contains(':')).map(|s| s.as_str()).collect();
            if !v4.is_empty() {
                let list = v4.join(" ");
                for svc in network_services() {
                    cmds.push(format!("networksetup -setdnsservers '{}' {}", svc, list));
                }
            }
        }

        run_as_admin(&cmds)
    }

    pub fn teardown(
        interface: &str,
        allowed_ips: &[String],
        dns: &[String],
    ) -> Result<(), String> {
        let mut cmds: Vec<String> = vec![];

        for cidr in allowed_ips {
            if cidr.contains(':') {
                continue;
            }
            if cidr == "0.0.0.0/0" || cidr == "0/0" {
                cmds.push(format!(
                    "route delete -net 0.0.0.0/1 -interface {}",
                    interface
                ));
                cmds.push(format!(
                    "route delete -net 128.0.0.0/1 -interface {}",
                    interface
                ));
            } else {
                cmds.push(format!("route delete -net {} -interface {}", cidr, interface));
            }
        }

        if !dns.is_empty() {
            for svc in network_services() {
                cmds.push(format!("networksetup -setdnsservers '{}' Empty", svc));
            }
        }

        run_as_admin(&cmds)
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

    fn run_as_admin(cmds: &[String]) -> Result<(), String> {
        if cmds.is_empty() {
            return Ok(());
        }
        let joined = cmds.join(" ; ");
        let escaped = joined.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            escaped
        );
        let out = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("osascript failed: {}", e))?;

        if out.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8_lossy(&out.stderr);
            Err(format!("Route setup failed: {}", msg))
        }
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
mod platform {
    use super::IfaceConfig;

    pub fn setup(
        interface: &str,
        iface_cfg: &IfaceConfig<'_>,
        allowed_ips: &[String],
        dns: &[String],
        peer_endpoint_ip: &str,
    ) -> Result<(), String> {
        let mut cmds: Vec<Vec<String>> = vec![];

        cmds.push(vec![
            "ip".into(),
            "addr".into(),
            "add".into(),
            format!("{}/{}", iface_cfg.addr, iface_cfg.prefix_len),
            "dev".into(),
            interface.to_string(),
        ]);
        cmds.push(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            interface.to_string(),
            "mtu".into(),
            iface_cfg.mtu.to_string(),
            "up".into(),
        ]);

        let gw_raw = default_gateway();
        if let Some(ref gw) = gw_raw {
            cmds.push(vec!["ip".into(), "route".into(), "add".into(), peer_endpoint_ip.to_string(), "via".into(), gw.clone()]);
        }

        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            cmds.push(vec!["ip".into(), "route".into(), "add".into(), cidr.clone(), "dev".into(), interface.to_string()]);
        }

        run_privileged(cmds)?;

        if !dns.is_empty() {
            let v4: Vec<String> = dns.iter().filter(|d| !d.contains(':')).cloned().collect();
            if !v4.is_empty() {
                let mut args = vec!["resolvectl".into(), "dns".into(), interface.to_string()];
                args.extend(v4);
                let _ = run_privileged(vec![args]);
            }
        }

        Ok(())
    }

    pub fn teardown(
        interface: &str,
        allowed_ips: &[String],
        dns: &[String],
    ) -> Result<(), String> {
        let mut cmds: Vec<Vec<String>> = vec![];

        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            cmds.push(vec!["ip".into(), "route".into(), "del".into(), cidr.clone(), "dev".into(), interface.to_string()]);
        }

        cmds.push(vec!["ip".into(), "link".into(), "set".into(), interface.to_string(), "down".into()]);

        if !dns.is_empty() {
            cmds.push(vec!["resolvectl".into(), "revert".into(), interface.to_string()]);
        }

        run_privileged(cmds)
    }

    fn default_gateway() -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        s.split_whitespace().skip_while(|t| *t != "via").nth(1).map(str::to_string)
    }

    fn run_privileged(cmds: Vec<Vec<String>>) -> Result<(), String> {
        for parts in cmds {
            if parts.is_empty() {
                continue;
            }
            let direct = std::process::Command::new(&parts[0])
                .args(&parts[1..])
                .output();
            if let Ok(o) = direct {
                if o.status.success() {
                    continue;
                }
            }
            let out = std::process::Command::new("pkexec")
                .args(&parts)
                .output()
                .map_err(|_| "pkexec not found. Install policykit-1.".to_string())?;
            if !out.status.success() {
                let e = String::from_utf8_lossy(&out.stderr);
                return Err(format!("Route command failed: {}", e));
            }
        }
        Ok(())
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────
#[cfg(target_os = "windows")]
mod platform {
    use super::IfaceConfig;

    pub fn setup(
        interface: &str,
        iface_cfg: &IfaceConfig<'_>,
        allowed_ips: &[String],
        dns: &[String],
        peer_endpoint_ip: &str,
    ) -> Result<(), String> {
        let mut cmds: Vec<String> = vec![];

        cmds.push(format!(
            "netsh interface ipv4 set address name=\"{}\" static {}/{}",
            interface, iface_cfg.addr, iface_cfg.prefix_len
        ));
        cmds.push(format!(
            "netsh interface ipv4 set subinterface \"{}\" mtu={} store=active",
            interface, iface_cfg.mtu
        ));

        if let Some(gw) = default_gateway() {
            cmds.push(format!(
                "route ADD {} MASK 255.255.255.255 {}",
                peer_endpoint_ip, gw
            ));
        }

        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            let (net, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
            cmds.push(format!(
                "netsh interface ipv4 add route {}/{} \"{}\" store=active",
                net, prefix, interface
            ));
        }

        if !dns.is_empty() {
            let v4: Vec<&str> = dns.iter().filter(|d| !d.contains(':')).map(|s| s.as_str()).collect();
            if !v4.is_empty() {
                cmds.push(format!(
                    "netsh interface ipv4 set dns name=\"{}\" static {}",
                    interface,
                    v4[0]
                ));
            }
        }

        run_elevated(&cmds)
    }

    pub fn teardown(
        interface: &str,
        allowed_ips: &[String],
        _dns: &[String],
    ) -> Result<(), String> {
        let mut cmds: Vec<String> = vec![];
        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            let (net, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
            cmds.push(format!(
                "netsh interface ipv4 delete route {}/{} \"{}\"",
                net, prefix, interface
            ));
        }
        run_elevated(&cmds)
    }

    fn default_gateway() -> Option<String> {
        let out = std::process::Command::new("powershell")
            .args(["-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    fn run_elevated(cmds: &[String]) -> Result<(), String> {
        if cmds.is_empty() {
            return Ok(());
        }
        let script = cmds.join("; ");
        let out = std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command \"{}\";'",
                    script.replace('"', "'")
                ),
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }
}
