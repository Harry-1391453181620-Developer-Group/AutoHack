use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY, Cell, Color, Table};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use rpassword::prompt_password;
use std::collections::HashSet;
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
    interface: String, // which interface it was found on
}

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
    println!("{}", style("    WSL Active Network Scanner & IP Enumerator • v0.2.0\n").dim());
    println!("{}", style("─────────────────────────────────────────────────────────────────────────────────────────────────────").dim());

    // 1. Securely ask for the WSL root password
    let password = prompt_password("Enter WSL root password: ").expect("Failed to read password");

    println!("\nFetching network interfaces from WSL...");

    // 2. Execute `ip addr show` via WSL
    let output = Command::new("wsl")
        .args(["-e", "ip", "addr", "show"])
        .output()
        .expect("Failed to execute WSL command. Is WSL installed and running?");

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    // 3. Parse the network interface data
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

            current_iface = Some(Interface {
                name,
                subnet: None,
                enabled,
            });
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

    // 4. Print Interfaces Table
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

    // 5. Render Interactive Menu for first-phase (netdiscover)
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

    // We'll collect all discovered hosts across all selected interfaces
    let mut all_hosts: Vec<DiscoveredHost> = Vec::new();

    // 6. Execute netdiscover on each target
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

                        // Store for later selection
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

    // 7. Check if any hosts were discovered
    if all_hosts.is_empty() {
        println!("\nNo hosts discovered. Exiting.");
        wait_for_exit();
        return;
    }

    // Deduplicate IPs (in case same IP appears on multiple interfaces)
    let mut unique_ips: Vec<String> = all_hosts
        .iter()
        .map(|h| h.ip.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique_ips.sort();

    // 8. Present second-phase selection: specific IP or All
    let mut ip_options: Vec<String> = unique_ips.clone();
    ip_options.push("All (time may be long)".to_string());

    let ip_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select an IP for detailed scanning, or choose All")
        .default(0)
        .items(&ip_options)
        .interact()
        .unwrap();

    // Define port lists as constants
    const PORTS_FULL: &str = "20,21,22,23,24,53,67,68,69,80,110,123,137,138,139,143,161,162,389,443,445,465,514,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";
    const PORTS_TCP_ONLY: &str = "20,21,22,23,80,110,139,143,443,445,465,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";
    // For UDP we use the full list (which includes UDP-specific ones like 67,68,123, etc.)

    if ip_selection < unique_ips.len() {
        // Single IP scan
        let ip = &unique_ips[ip_selection];
        println!("\nStarting detailed scan on target {} ...", ip);

        let cmd = format!(
            "echo '{}' | sudo -S nmap -sU -sS --min-rate 1000 -p {} {}",
            password, PORTS_FULL, ip
        );

        let nmap_output = Command::new("wsl")
            .args(["-e", "bash", "-c", &cmd])
            .output()
            .expect("Failed to execute nmap");

        let nmap_str = String::from_utf8_lossy(&nmap_output.stdout);
        let ports = parse_nmap_output(&nmap_str);

        display_port_table(&ports, &format!("Results for {}", ip));
    } else {
        // All: scan each selected interface's subnet with TCP and UDP
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
                let tcp_ports = parse_nmap_output(&tcp_str);

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
                let udp_ports = parse_nmap_output(&udp_str);

                // Combine both sets
                let mut combined = tcp_ports;
                combined.extend(udp_ports);
                // Sort by port number then protocol
                combined.sort_by_key(|p| (p.port, p.protocol.clone()));

                display_port_table(&combined, &format!("Interface {} ({})", target.name, subnet));
            }
        }
    }

    wait_for_exit();
}

fn parse_nmap_output(output: &str) -> Vec<PortInfo> {
    let re = Regex::new(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.*)$").unwrap();
    let mut ports = Vec::new();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            let port: u16 = caps[1].parse().unwrap_or(0);
            let protocol = caps[2].to_string();
            let state = caps[3].to_string();
            let service = caps[4].trim().to_string();
            if port > 0 {
                ports.push(PortInfo { port, protocol, state, service });
            }
        }
    }
    ports
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