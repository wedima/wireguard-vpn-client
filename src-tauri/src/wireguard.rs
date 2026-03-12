pub struct IfaceConfig<'a> {
    pub addr: &'a str,
    pub prefix_len: u8,
    pub addr6: Option<(&'a str, u8)>,
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

        if let Some((addr6, plen6)) = iface_cfg.addr6 {
            cmds.push(format!(
                "ifconfig {} inet6 {} prefixlen {} up",
                interface, addr6, plen6
            ));
        }

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

        if let Some((addr6, plen6)) = iface_cfg.addr6 {
            cmds.push(vec![
                "ip".into(),
                "addr".into(),
                "add".into(),
                format!("{}/{}", addr6, plen6),
                "dev".into(),
                interface.to_string(),
            ]);
        }

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
    use crate::wg_config::cidr_to_netmask;

    pub fn setup(
        interface: &str,
        iface_cfg: &IfaceConfig<'_>,
        allowed_ips: &[String],
        dns: &[String],
        peer_endpoint_ip: &str,
    ) -> Result<(), String> {
        let netmask = cidr_to_netmask(iface_cfg.prefix_len);

        // Set IP and MTU
        run_cmd("netsh", &[
            "interface", "ipv4", "set", "address",
            &format!("name={}", interface),
            "static", iface_cfg.addr, &netmask,
            "gateway=none",
        ])?;

        run_cmd("netsh", &[
            "interface", "ipv4", "set", "subinterface",
            interface,
            &format!("mtu={}", iface_cfg.mtu),
            "store=active",
        ])?;

        // Set interface metric to 1 to ensure it's preferred
        run_cmd("netsh", &[
            "interface", "ipv4", "set", "interface",
            interface,
            "metric=1",
        ])?;

        run_cmd("netsh", &[
            "interface", "ipv6", "set", "interface",
            interface,
            "metric=1",
        ])?;

        // Get interface index for precise routing
        let if_index = get_interface_index(interface)?;

        // Route peer endpoint via original gateway
        if let Some(gw) = default_gateway() {
            let _ = run_cmd("route", &[
                "ADD", peer_endpoint_ip, "MASK", "255.255.255.255", &gw, "METRIC", "1",
            ]);
        }

        // Add tunnel routes
        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            if cidr == "0.0.0.0/0" || cidr == "0/0" {
                // Use the interface index (IF x) and the interface's own IP as gateway
                let _ = run_cmd("route", &["ADD", "0.0.0.0", "MASK", "128.0.0.0", iface_cfg.addr, "IF", &if_index]);
                let _ = run_cmd("route", &["ADD", "128.0.0.0", "MASK", "128.0.0.0", iface_cfg.addr, "IF", &if_index]);
            } else {
                let (net, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
                let mask = cidr_to_netmask(prefix.parse().unwrap_or(32));
                let _ = run_cmd("route", &["ADD", net, "MASK", &mask, iface_cfg.addr, "IF", &if_index]);
            }
        }

        // DNS configuration
        if !dns.is_empty() {
            let v4: Vec<&str> = dns.iter().filter(|d| !d.contains(':')).map(|s| s.as_str()).collect();
            if !v4.is_empty() {
                let _ = run_cmd("netsh", &[
                    "interface", "ipv4", "set", "dnsservers",
                    &format!("name={}", interface),
                    "static", v4[0], "primary", "validate=no",
                ]);
                for extra in &v4[1..] {
                    let _ = run_cmd("netsh", &[
                        "interface", "ipv4", "add", "dnsservers",
                        &format!("name={}", interface),
                        extra, "validate=no",
                    ]);
                }
            }
            
            let v6: Vec<&str> = dns.iter().filter(|d| d.contains(':')).map(|s| s.as_str()).collect();
            if !v6.is_empty() {
                let _ = run_cmd("netsh", &[
                    "interface", "ipv6", "set", "dnsservers",
                    &format!("name={}", interface),
                    "static", v6[0], "primary", "validate=no",
                ]);
                for extra in &v6[1..] {
                    let _ = run_cmd("netsh", &[
                        "interface", "ipv6", "add", "dnsservers",
                        &format!("name={}", interface),
                        extra, "validate=no",
                    ]);
                }
            }
        }

        // IPv6 Handling & Leak Protection
        if let Some((addr6, plen6)) = iface_cfg.addr6 {
            // VPN supports IPv6: Configure it
            let _ = run_cmd("netsh", &[
                "interface", "ipv6", "set", "address",
                &format!("name={}", interface),
                &format!("{}/{}", addr6, plen6),
                "store=active",
            ]);

            // Routing for IPv6
            for cidr6 in allowed_ips.iter().filter(|c| c.contains(':')) {
                if cidr6 == "::/0" {
                    let _ = run_ps(&format!("New-NetRoute -DestinationPrefix '::/1' -InterfaceIndex {} -NextHop '::' -RouteMetric 0 -ErrorAction SilentlyContinue", if_index));
                    let _ = run_ps(&format!("New-NetRoute -DestinationPrefix '8000::/1' -InterfaceIndex {} -NextHop '::' -RouteMetric 0 -ErrorAction SilentlyContinue", if_index));
                } else {
                    let _ = run_ps(&format!("New-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '::' -RouteMetric 0 -ErrorAction SilentlyContinue", cidr6, if_index));
                }
            }
        } else {
            // VPN does NOT support IPv6: Block leaks by blackholing
            // Assign dummy address to make IPv6 stack active and routing work on this interface
            let _ = run_cmd("netsh", &[
                "interface", "ipv6", "set", "address",
                &format!("name={}", interface),
                "fd00:dead:beef:ffff::1/128",
                "store=active",
            ]);

            // Add routes via PowerShell with metric 0 (highest priority)
            let _ = run_ps(&format!("New-NetRoute -DestinationPrefix '::/1' -InterfaceIndex {} -NextHop '::' -RouteMetric 0 -ErrorAction SilentlyContinue", if_index));
            let _ = run_ps(&format!("New-NetRoute -DestinationPrefix '8000::/1' -InterfaceIndex {} -NextHop '::' -RouteMetric 0 -ErrorAction SilentlyContinue", if_index));
        }

        Ok(())
    }

    pub fn teardown(
        interface: &str,
        allowed_ips: &[String],
        _dns: &[String],
    ) -> Result<(), String> {
        // Remove IPv4 routes
        for cidr in allowed_ips.iter().filter(|c| !c.contains(':')) {
            if cidr == "0.0.0.0/0" || cidr == "0/0" {
                let _ = run_cmd("route", &["DELETE", "0.0.0.0", "MASK", "128.0.0.0"]);
                let _ = run_cmd("route", &["DELETE", "128.0.0.0", "MASK", "128.0.0.0"]);
            } else {
                let (net, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
                let mask = cidr_to_netmask(prefix.parse().unwrap_or(32));
                let _ = run_cmd("route", &["DELETE", net, "MASK", &mask]);
            }
        }

        // Remove IPv6 routes / Leak protection via PowerShell for precision
        let _ = run_ps("Remove-NetRoute -DestinationPrefix '::/1' -Confirm:$false -ErrorAction SilentlyContinue");
        let _ = run_ps("Remove-NetRoute -DestinationPrefix '8000::/1' -Confirm:$false -ErrorAction SilentlyContinue");
        for cidr6 in allowed_ips.iter().filter(|c| c.contains(':')) {
            if cidr6 != "::/0" {
                let _ = run_ps(&format!("Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue", cidr6));
            }
        }

        let _ = run_cmd("netsh", &[
            "interface", "ipv4", "set", "dnsservers",
            &format!("name={}", interface),
            "dhcp",
        ]);
        let _ = run_cmd("netsh", &[
            "interface", "ipv6", "set", "dnsservers",
            &format!("name={}", interface),
            "dhcp",
        ]);
        Ok(())
    }

    fn run_ps(cmd: &str) -> Result<(), String> {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
            .output()
            .map_err(|e| format!("powershell: {}", e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn get_interface_index(name: &str) -> Result<String, String> {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                &format!("(Get-NetAdapter -Name '{}').InterfaceIndex", name),
            ])
            .output()
            .map_err(|e| e.to_string())?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            Err(format!("Could not find interface index for {}", name))
        } else {
            Ok(s)
        }
    }

    fn default_gateway() -> Option<String> {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("{}: {}", program, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}
