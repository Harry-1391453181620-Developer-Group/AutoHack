use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY, Cell, Color, Table};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use rpassword::prompt_password;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

#[derive(Clone)]
struct Interface {
    name: String,
    subnet: Option<String>,
    enabled: bool,
}

struct DiscoveredHost {
    ip: String,
    mac: String,
    vendor: String,
    interface: String,
}

#[derive(Clone)]
struct PortInfo {
    port: u16,
    protocol: String, // "tcp" or "udp"
    state: String,
    service: String,
}

fn main() {
    let term = Term::stdout();
    let _ = term.show_cursor();

    println!("{}", style(r#"
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝
███████║██║   ██║   ██║   ██║   ██║███████║███████║██║     █████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██╔══██║██╔══██║██║     ██╔═██╗
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                      -- By Harry-1391453181620 DG
    "#).cyan().bold());
    println!("{}", style("    WSL Active Network Scanner & IP Enumerator • v0.3.0\n").dim());
    println!("{}", style("─────────────────────────────────────────────────────────────────────────────────────────────────────").dim());

    let password = prompt_password("Enter WSL root password: ").expect("Failed to read password");
    println!("\nFetching network interfaces from WSL...");

    let output = Command::new("wsl")
        .args(["-e", "ip", "addr", "show"])
        .output()
        .expect("Failed to execute WSL command. Is WSL installed and running?");

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut current_iface: Option<Interface> = None;

    let re_iface = Regex::new(r"^\d+:\s+([^:]+):\s+<([^>]+)>").unwrap();
    let re_inet = Regex::new(r"^\s*inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/\d+").unwrap();

    for line in stdout_str.lines() {
        if let Some(caps) = re_iface.captures(line) {
            if let Some(iface) = current_iface.take() {
                interfaces.push(iface);
            }
            let name = caps[1].to_string();
            let flags = caps[2].to_string();
            let enabled = flags.contains("UP");
            current_iface = Some(Interface { name, subnet: None, enabled });
        } else if let Some(caps) = re_inet.captures(line) {
            if let Some(ref mut iface) = current_iface {
                if iface.subnet.is_none() {
                    iface.subnet = Some(format!("{}.0/24", &caps[1]));
                }
            }
        }
    }
    if let Some(iface) = current_iface.take() {
        interfaces.push(iface);
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Interface").fg(Color::Cyan),
            Cell::new("Subnet").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
        ]);

    for iface in &interfaces {
        let subnet_str = iface.subnet.clone().unwrap_or_else(|| "/".to_string());
        let status_cell = if iface.enabled {
            Cell::new("Enable").fg(Color::Green)
        } else {
            Cell::new("Disable").fg(Color::DarkGrey)
        };
        table.add_row(vec![
            Cell::new(&iface.name),
            Cell::new(subnet_str),
            status_cell,
        ]);
    }
    println!("\n{table}\n");

    let mut options = vec!["All (Scan all valid subnets)".to_string()];
    options.extend(interfaces.iter().map(|i| i.name.clone()));

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Which interface(s) do you want to discover?")
        .default(0)
        .items(&options)
        .interact()
        .unwrap();

    let targets: Vec<&Interface> = if selection == 0 {
        interfaces.iter().filter(|i| i.subnet.is_some()).collect()
    } else {
        vec![&interfaces[selection - 1]]
    };

    let mut all_hosts: Vec<DiscoveredHost> = Vec::new();

    for target in &targets {
        if let Some(subnet) = &target.subnet {
            println!("\nScanning [{}] on subnet [{}]... Please wait...", target.name, subnet);

            let cmd = format!(
                "echo '{}' | sudo -S netdiscover -i {} -r {} -P",
                password, target.name, subnet
            );

            let scan_output = Command::new("wsl")
                .args(["-e", "bash", "-c", &cmd])
                .output()
                .expect("Failed to execute netdiscover inside WSL");

            let scan_str = String::from_utf8_lossy(&scan_output.stdout);

            let mut result_table = Table::new();
            result_table
                .load_preset(UTF8_BORDERS_ONLY)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("IP Address").fg(Color::Green),
                    Cell::new("MAC Address").fg(Color::Yellow),
                    Cell::new("Vendor / Hostname").fg(Color::Blue),
                ]);

            let mut hosts_found = false;

            for line in scan_str.lines() {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if tokens.len() >= 5 {
                    if tokens[0].parse::<Ipv4Addr>().is_ok() {
                        let ip = tokens[0].to_string();
                        let mac = tokens[1].to_string();
                        let vendor = tokens[4..].join(" ");
                        result_table.add_row(vec![&ip, &mac, &vendor]);
                        hosts_found = true;
                        all_hosts.push(DiscoveredHost {
                            ip,
                            mac,
                            vendor,
                            interface: target.name.clone(),
                        });
                    }
                }
            }

            println!("\n>> Discovery Results for {} ({}) <<", target.name, subnet);
            if hosts_found {
                println!("{result_table}");
            } else {
                println!("No active hosts responded on this network segment.");
            }
        } else {
            println!("\n[!] Skipping interface '{}': No valid subnet found.", target.name);
        }
    }

    if all_hosts.is_empty() {
        println!("\nNo hosts discovered. Exiting.");
        wait_for_exit();
        return;
    }

    let mut unique_ips: Vec<String> = all_hosts
        .iter()
        .map(|h| h.ip.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique_ips.sort();

    let mut ip_options: Vec<String> = unique_ips.clone();
    ip_options.push("All (time may be long)".to_string());

    let ip_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select an IP for detailed scanning, or choose All")
        .default(0)
        .items(&ip_options)
        .interact()
        .unwrap();

    const PORTS_FULL: &str = "20,21,22,23,24,53,67,68,69,80,110,123,137,138,139,143,161,162,389,443,445,465,514,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";
    const PORTS_TCP_ONLY: &str = "20,21,22,23,80,110,139,143,443,445,465,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";

    if ip_selection < unique_ips.len() {
        // Single IP: run TCP and UDP separately, then merge
        let ip = &unique_ips[ip_selection];
        println!("\nStarting detailed scan on target {} ...", ip);

        // TCP scan
        let cmd_tcp = format!(
            "echo '{}' | sudo -S nmap -sS --min-rate 1000 -p {} {}",
            password, PORTS_TCP_ONLY, ip
        );
        let out_tcp = Command::new("wsl")
            .args(["-e", "bash", "-c", &cmd_tcp])
            .output()
            .expect("Failed to run TCP nmap");
        let tcp_str = String::from_utf8_lossy(&out_tcp.stdout);
        let tcp_hosts = parse_nmap_output_grouped(&tcp_str);

        // UDP scan
        let cmd_udp = format!(
            "echo '{}' | sudo -S nmap -sU --min-rate 1000 -p {} {}",
            password, PORTS_FULL, ip
        );
        let out_udp = Command::new("wsl")
            .args(["-e", "bash", "-c", &cmd_udp])
            .output()
            .expect("Failed to run UDP nmap");
        let udp_str = String::from_utf8_lossy(&out_udp.stdout);
        let udp_hosts = parse_nmap_output_grouped(&udp_str);

        let mut merged: Vec<PortInfo> = Vec::new();
        if let Some((_, ports)) = tcp_hosts.first() {
            merged.extend(ports.iter().cloned());
        }
        if let Some((_, ports)) = udp_hosts.first() {
            merged.extend(ports.iter().cloned());
        }
        merged.sort_by_key(|p| (p.port, p.protocol.clone()));
        display_port_table(&merged, &format!("Results for {}", ip));
    } else {
        // All: scan each interface's subnet, then show per-host tables
        for target in &targets {
            if let Some(subnet) = &target.subnet {
                println!("\n--- Scanning interface {} on subnet {} ---", target.name, subnet);

                // TCP scan
                let cmd_tcp = format!(
                    "echo '{}' | sudo -S nmap -e {} {} -sS -T4 --min-rate 1000 -p {}",
                    password, target.name, subnet, PORTS_TCP_ONLY
                );
                let out_tcp = Command::new("wsl")
                    .args(["-e", "bash", "-c", &cmd_tcp])
                    .output()
                    .expect("Failed to run TCP nmap");
                let tcp_str = String::from_utf8_lossy(&out_tcp.stdout);
                let tcp_hosts = parse_nmap_output_grouped(&tcp_str);

                // UDP scan
                let cmd_udp = format!(
                    "echo '{}' | sudo -S nmap -e {} {} -sU --min-rate 1000 -p {}",
                    password, target.name, subnet, PORTS_FULL
                );
                let out_udp = Command::new("wsl")
                    .args(["-e", "bash", "-c", &cmd_udp])
                    .output()
                    .expect("Failed to run UDP nmap");
                let udp_str = String::from_utf8_lossy(&out_udp.stdout);
                let udp_hosts = parse_nmap_output_grouped(&udp_str);

                // Merge ports for each IP (combine TCP and UDP results)
                let mut host_map: HashMap<String, Vec<PortInfo>> = HashMap::new();
                for (ip, ports) in tcp_hosts {
                    host_map.entry(ip).or_default().extend(ports);
                }
                for (ip, ports) in udp_hosts {
                    host_map.entry(ip).or_default().extend(ports);
                }

                // Display one table per host
                for (ip, mut ports) in host_map {
                    ports.sort_by_key(|p| (p.port, p.protocol.clone()));
                    display_port_table(&ports, &format!("Host {} (via {})", ip, target.name));
                }
            }
        }
    }

    wait_for_exit();
}

/// Parse nmap output and group port lines by target IP
fn parse_nmap_output_grouped(output: &str) -> Vec<(String, Vec<PortInfo>)> {
    let mut results = Vec::new();
    let re_ip = Regex::new(r"Nmap scan report for (\S+)").unwrap();
    let re_port = Regex::new(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.*)$").unwrap();

    let mut current_ip = String::new();
    let mut current_ports = Vec::new();

    for line in output.lines() {
        if let Some(caps) = re_ip.captures(line) {
            // Save previous host if any
            if !current_ip.is_empty() {
                results.push((current_ip.clone(), std::mem::take(&mut current_ports)));
            }
            current_ip = caps[1].to_string();
        } else if let Some(caps) = re_port.captures(line) {
            let port: u16 = caps[1].parse().unwrap_or(0);
            let protocol = caps[2].to_string();
            let state = caps[3].to_string();
            let service = caps[4].trim().to_string();
            if port > 0 {
                current_ports.push(PortInfo { port, protocol, state, service });
            }
        }
    }
    // Push the last one
    if !current_ip.is_empty() {
        results.push((current_ip, current_ports));
    }
    results
}

fn display_port_table(ports: &[PortInfo], title: &str) {
    if ports.is_empty() {
        println!("{}: No open ports detected.", title);
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Port").fg(Color::Cyan),
            Cell::new("Protocol").fg(Color::Cyan),
            Cell::new("State").fg(Color::Cyan),
            Cell::new("Service").fg(Color::Cyan),
        ]);

    for p in ports {
        table.add_row(vec![
            Cell::new(&p.port.to_string()),
            Cell::new(&p.protocol),
            Cell::new(&p.state),
            Cell::new(&p.service),
        ]);
    }

    println!("\n{}", title);
    println!("{table}");
}

fn wait_for_exit() {
    println!("\nDone. Press the [e] key to close this terminal window.");
    let term = Term::stdout();
    loop {
        match term.read_key() {
            Ok(console::Key::Char('e') | console::Key::Char('E')) => break,
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}