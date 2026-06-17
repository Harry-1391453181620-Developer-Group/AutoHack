use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY, Cell, Color, Table};
use console::Term;
use dialoguer::{theme::ColorfulTheme, Select};
use regex::Regex;
use rpassword::prompt_password;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

#[derive(Clone)]
struct Interface {
    name: String,
    subnet: Option<String>,
    enabled: bool,
}

fn main() {
    let term = Term::stdout();
    let _ = term.show_cursor();

    println!("=== WSL Network Detector ===\n");

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

    // 5. Render Interactive Menu
    let mut options = vec!["All (Scan all valid subnets)".to_string()];
    options.extend(interfaces.iter().map(|i| i.name.clone()));

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Which do you want to detect?")
        .default(0)
        .items(&options)
        .interact()
        .unwrap();

    // 6. Filter Targets
    let targets: Vec<&Interface> = if selection == 0 {
        interfaces.iter().filter(|i| i.subnet.is_some()).collect()
    } else {
        vec![&interfaces[selection - 1]]
    };

    // 7. Execute netdiscover with non-interactive parsing mode (-P)
    for target in targets {
        if let Some(subnet) = &target.subnet {
            println!("\nScanning [{}] on subnet [{}]... Please wait...", target.name, subnet);

            // Using the -P flag to force a single clean active scan that exits automatically
            let cmd = format!("echo '{}' | sudo -S netdiscover -i {} -r {} -P", password, target.name, subnet);

            let scan_output = Command::new("wsl")
                .args(["-e", "bash", "-c", &cmd])
                .output()
                .expect("Failed to execute netdiscover inside WSL");

            let scan_str = String::from_utf8_lossy(&scan_output.stdout);

            // Prepare a tidy table for the discovered IPs
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

            // Extract rows containing unique discovered targets safely
            for line in scan_str.lines() {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                // A valid row contains at least: IP, MAC, Count, Len, Vendor
                if tokens.len() >= 5 {
                    if tokens[0].parse::<Ipv4Addr>().is_ok() {
                        let ip = tokens[0];
                        let mac = tokens[1];
                        let vendor = tokens[4..].join(" "); // Re-join multi-word vendors cleanly

                        result_table.add_row(vec![ip, mac, &vendor]);
                        hosts_found = true;
                    }
                }
            }

            println!("\n>> Discovery Results for {} ({}) <<", target.name, subnet);
            if hosts_found {
                println!("{result_table}");
            } else {
                println!("⚠️ No active hosts responded on this network segment.");
            }
        } else {
            println!("\n[!] Skipping interface '{}': No valid subnet found.", target.name);
        }
    }

    // 8. Secure Exit Gate
    println!("\n🚀 Done! Press the [e] key to close this terminal window.");
    loop {
        match term.read_key() {
            Ok(console::Key::Char('e') | console::Key::Char('E')) => {
                break;
            }
            Ok(_) => {}
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}