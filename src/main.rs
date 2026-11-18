use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS,
    presets::UTF8_BORDERS_ONLY,
    Cell,
    Color,
    Table,
};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Select};
use regex::Regex;
use rpassword::prompt_password;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::{self, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

#[derive(Clone)]
struct Interface {
    name: String,
    subnet: Option<String>,
    enabled: bool,
}

#[derive(Clone)]
struct PortInfo {
    port: u16,
    protocol: String, // "tcp" or "udp"
    state: String,
    service: String,
}

const PORTS_FULL: &str = "20,21,22,23,24,53,67,68,69,80,110,123,137,138,139,143,161,162,389,443,445,465,514,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";
const PORTS_TCP_ONLY: &str = "20,21,22,23,80,110,139,143,443,445,465,587,636,993,995,1080,1433,3306,3389,8080,5432,6379,27017";

fn main() {
    if let Err(error) = run() {
        eprintln!("\nError: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    let _ = term.show_cursor();

    println!(
        "{}",
        style(
            r#"
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝
███████║██║   ██║   ██║   ██║   ██║███████║███████║██║     █████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██╔══██║██╔══██║██║     ██╔═██╗
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                      -- By Harry-1391453181620 DG
"#
        )
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("    WSL Active Network Scanner & IP Enumerator • v0.3.0\n").dim()
    );
    println!(
        "{}",
        style("─────────────────────────────────────────────────────────────────────────────────────────────────────").dim()
    );

    println!("\nThis tool should only be used on networks you own or are explicitly authorised to assess.");
    let authorised = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you have permission to scan the selected network(s)?")
        .default(false)
        .interact()?;
    if !authorised {
        println!("Scan cancelled.");
        return Ok(());
    }

    let is_root = current_user_is_root()?;
    let sudo_password = if is_root {
        None
    } else {
        Some(prompt_password("Enter Linux sudo password: ")?)
    };

    println!("\nFetching network interfaces from Linux...");

    // This program now runs inside WSL, so call Linux utilities directly.
    // There is no reason to invoke `wsl.exe` from inside Linux.
    let output = run_unprivileged("ip", &["addr", "show"])?;
    let stdout_str = String::from_utf8_lossy(&output.stdout);

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut current_iface: Option<Interface> = None;

    let re_iface = Regex::new(r"^\d+:\s+([^:]+):\s+<([^>]+)>")?;
    let re_inet = Regex::new(r"^\s*inet\s+((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})")?;

    for line in stdout_str.lines() {
        if let Some(caps) = re_iface.captures(line) {
            if let Some(iface) = current_iface.take() {
                interfaces.push(iface);
            }

            let name = caps[1].to_string();
            let flags = caps[2].to_string();
            let enabled = flags.split(',').any(|flag| flag == "UP");
            current_iface = Some(Interface {
                name,
                subnet: None,
                enabled,
            });
        } else if let Some(caps) = re_inet.captures(line) {
            if let Some(iface) = current_iface.as_mut() {
                if iface.subnet.is_none() {
                    let address: Ipv4Addr = caps[1].parse()?;
                    let prefix: u32 = caps[2].parse()?;

                    // Ignore loopback/unspecified addresses. Keep discovery scope
                    // no broader than a /24; respect narrower interface subnets.
                    // This avoids accidentally expanding a /16 interface into a
                    // scan of the entire /16 network.
                    if !address.is_loopback() && !address.is_unspecified() && prefix <= 32 {
                        let scan_prefix = prefix.max(24);
                        let mask = u32::MAX << (32 - scan_prefix);
                        let network = Ipv4Addr::from(u32::from(address) & mask);
                        iface.subnet = Some(format!("{network}/{scan_prefix}"));
                    }
                }
            }
        }
    }

    if let Some(iface) = current_iface.take() {
        interfaces.push(iface);
    }

    if interfaces.is_empty() {
        println!("No network interfaces were found.");
        wait_for_exit();
        return Ok(());
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
            Cell::new("Enabled").fg(Color::Green)
        } else {
            Cell::new("Disabled").fg(Color::DarkGrey)
        };
        table.add_row(vec![
            Cell::new(&iface.name),
            Cell::new(subnet_str),
            status_cell,
        ]);
    }
    println!("\n{table}\n");

    let scanable_interfaces: Vec<&Interface> = interfaces
        .iter()
        .filter(|iface| iface.enabled && iface.subnet.is_some())
        .collect();

    if scanable_interfaces.is_empty() {
        println!("No enabled non-loopback IPv4 interfaces with a subnet were found.");
        wait_for_exit();
        return Ok(());
    }

    let mut options = vec!["All (Scan all valid subnets)".to_string()];
    options.extend(
        scanable_interfaces
            .iter()
            .map(|iface| iface.name.clone()),
    );

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Which interface(s) do you want to discover?")
        .default(0)
        .items(&options)
        .interact()?;

    let targets: Vec<&Interface> = if selection == 0 {
        scanable_interfaces
    } else {
        vec![scanable_interfaces[selection - 1]]
    };

    // Store only the IP addresses: the original MAC/vendor/interface fields
    // were populated but never read, which triggered Rust's dead_code warning.
    let mut all_hosts: HashSet<String> = HashSet::new();

    for target in &targets {
        if let Some(subnet) = &target.subnet {
            println!(
                "\nDiscovering hosts on [{}], subnet [{}]...",
                target.name, subnet
            );

            let scan_output = run_privileged(
                "netdiscover",
                &["-i", target.name.as_str(), "-r", subnet.as_str(), "-P"],
                is_root,
                sudo_password.as_deref(),
            )?;
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
                    if let Ok(parsed_ip) = tokens[0].parse::<Ipv4Addr>() {
                        let ip = parsed_ip.to_string();
                        let mac = tokens[1];
                        let vendor = tokens[4..].join(" ");

                        result_table.add_row(vec![
                            Cell::new(&ip),
                            Cell::new(mac),
                            Cell::new(&vendor),
                        ]);
                        hosts_found = true;
                        all_hosts.insert(ip);
                    }
                }
            }

            println!("\n>> Discovery Results for {} ({}) <<", target.name, subnet);
            if hosts_found {
                println!("{result_table}");
            } else {
                println!("No active hosts responded on this network segment.");
            }
        }
    }

    if all_hosts.is_empty() {
        println!("\nNo hosts discovered. Exiting.");
        wait_for_exit();
        return Ok(());
    }

    let mut unique_ips: Vec<String> = all_hosts.into_iter().collect();
    unique_ips.sort();

    let mut ip_options: Vec<String> = unique_ips.clone();
    ip_options.push("All (time may be long)".to_string());

    let ip_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a discovered IP for detailed scanning, or choose All")
        .default(0)
        .items(&ip_options)
        .interact()?;

    if ip_selection < unique_ips.len() {
        // Detailed TCP and UDP checks for one discovered host.
        let ip = unique_ips[ip_selection].as_str();
        println!("\nStarting detailed scan on target {} ...", ip);

        let out_tcp = run_privileged(
            "nmap",
            &[
                "-sS",
                "--min-rate",
                "1000",
                "-p",
                PORTS_TCP_ONLY,
                ip,
            ],
            is_root,
            sudo_password.as_deref(),
        )?;
        let tcp_str = String::from_utf8_lossy(&out_tcp.stdout);
        let tcp_hosts = parse_nmap_output_grouped(&tcp_str);

        let out_udp = run_privileged(
            "nmap",
            &["-sU", "--min-rate", "1000", "-p", PORTS_FULL, ip],
            is_root,
            sudo_password.as_deref(),
        )?;
        let udp_str = String::from_utf8_lossy(&out_udp.stdout);
        let udp_hosts = parse_nmap_output_grouped(&udp_str);

        let mut merged: Vec<PortInfo> = Vec::new();
        if let Some((_, ports)) = tcp_hosts.first() {
            merged.extend(ports.iter().cloned());
        }
        if let Some((_, ports)) = udp_hosts.first() {
            merged.extend(ports.iter().cloned());
        }
        merged.sort_by_key(|port| (port.port, port.protocol.clone()));
        display_port_table(&merged, &format!("Results for {ip}"));
    } else {
        // Scan each selected interface subnet and group results by host.
        for target in &targets {
            if let Some(subnet) = &target.subnet {
                println!(
                    "\n--- Scanning interface {} on subnet {} ---",
                    target.name, subnet
                );

                let out_tcp = run_privileged(
                    "nmap",
                    &[
                        "-e",
                        target.name.as_str(),
                        subnet.as_str(),
                        "-sS",
                        "-T4",
                        "--min-rate",
                        "1000",
                        "-p",
                        PORTS_TCP_ONLY,
                    ],
                    is_root,
                    sudo_password.as_deref(),
                )?;
                let tcp_str = String::from_utf8_lossy(&out_tcp.stdout);
                let tcp_hosts = parse_nmap_output_grouped(&tcp_str);

                let out_udp = run_privileged(
                    "nmap",
                    &[
                        "-e",
                        target.name.as_str(),
                        subnet.as_str(),
                        "-sU",
                        "--min-rate",
                        "1000",
                        "-p",
                        PORTS_FULL,
                    ],
                    is_root,
                    sudo_password.as_deref(),
                )?;
                let udp_str = String::from_utf8_lossy(&out_udp.stdout);
                let udp_hosts = parse_nmap_output_grouped(&udp_str);

                let mut host_map: HashMap<String, Vec<PortInfo>> = HashMap::new();
                for (ip, ports) in tcp_hosts {
                    host_map.entry(ip).or_default().extend(ports);
                }
                for (ip, ports) in udp_hosts {
                    host_map.entry(ip).or_default().extend(ports);
                }

                let mut hosts: Vec<(String, Vec<PortInfo>)> = host_map.into_iter().collect();
                hosts.sort_by(|left, right| left.0.cmp(&right.0));

                for (ip, mut ports) in hosts {
                    ports.sort_by_key(|port| (port.port, port.protocol.clone()));
                    display_port_table(
                        &ports,
                        &format!("Host {} (via {})", ip, target.name),
                    );
                }
            }
        }
    }

    wait_for_exit();
    Ok(())
}

/// Returns true when the current Linux process has UID 0.
fn current_user_is_root() -> io::Result<bool> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        return Err(io::Error::other("Could not determine the current Linux user ID."));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "0")
}

/// Execute an unprivileged Linux command directly, without a shell or `wsl.exe`.
fn run_unprivileged(program: &str, args: &[&str]) -> io::Result<Output> {
    let output = Command::new(program).args(args).output()?;
    ensure_success(program, &output)?;
    Ok(output)
}

/// Execute a command directly. If this process is not root, use sudo and pass
/// the password through stdin rather than embedding it in a shell command.
fn run_privileged(
    program: &str,
    args: &[&str],
    is_root: bool,
    sudo_password: Option<&str>,
) -> io::Result<Output> {
    let output = if is_root {
        Command::new(program).args(args).output()?
    } else {
        let mut child = Command::new("sudo")
            .args(["-k", "-S", "-p", "", "--", program])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(sudo_password.unwrap_or_default().as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        child.wait_with_output()?
    };

    ensure_success(program, &output)?;
    Ok(output)
}

fn ensure_success(program: &str, output: &Output) -> io::Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "{program} exited with status {}: {}",
            output.status,
            stderr.trim()
        )))
    }
}

/// Parse nmap output and group port lines by target IP.
fn parse_nmap_output_grouped(output: &str) -> Vec<(String, Vec<PortInfo>)> {
    let mut results = Vec::new();
    let re_ip = Regex::new(r"Nmap scan report for (\S+)").expect("Invalid IP regex");
    let re_port = Regex::new(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.*)$")
        .expect("Invalid port regex");

    let mut current_ip = String::new();
    let mut current_ports = Vec::new();

    for line in output.lines() {
        if let Some(caps) = re_ip.captures(line) {
            if !current_ip.is_empty() {
                results.push((
                    current_ip.clone(),
                    std::mem::take(&mut current_ports),
                ));
            }
            current_ip = caps[1].to_string();
        } else if let Some(caps) = re_port.captures(line) {
            let port: u16 = caps[1].parse().unwrap_or(0);
            let protocol = caps[2].to_string();
            let state = caps[3].to_string();
            let service = caps[4].trim().to_string();

            if port > 0 {
                current_ports.push(PortInfo {
                    port,
                    protocol,
                    state,
                    service,
                });
            }
        }
    }

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

    for port in ports {
        table.add_row(vec![
            Cell::new(port.port.to_string()),
            Cell::new(&port.protocol),
            Cell::new(&port.state),
            Cell::new(&port.service),
        ]);
    }

    println!("\n{title}");
    println!("{table}");
}

fn wait_for_exit() {
    // Avoid waiting forever when RustRover runs the program without an
    // interactive terminal attached.
    if !io::stdin().is_terminal() {
        return;
    }

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
