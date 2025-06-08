use clap::Parser;
use colored::Colorize;
use futures::stream::{self, FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

mod fingerprint;

const ASCII_ART: &str = r#"
 ____            _     ____              
|  _ \ ___  _ __| |_  |  _ \  ___   __ _ 
| |_) / _ \| '__| __| | | | |/ _ \ / _` |
|  __/ (_) | |  | |_  | |_| | (_) | (_| |
|_|   \___/|_|   \__| |____/ \___/ \__, |
                                   |___/ 
A lightning-fast port scanner built with Rust.
"#;

#[derive(Serialize)]
struct ScanReport {
    target: String,
    open_ports: Vec<PortReport>,
}

#[derive(Serialize)]
struct PortReport {
    port: u16,
    state: &'static str,
    service: String,
    banner: String,
}

/// A lightning-fast asynchronous port scanner with adaptive timing and fingerprinting.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The IP address to scan.
    #[arg(required = true)]
    ipaddr: IpAddr,

    /// Ports to scan. Ex: 80,443 | 1-1024 | -
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Set timing template (0-5, default: 3). Higher is faster and more aggressive.
    #[arg(short = 'T', long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(0..=5))]
    timing: u8,

    /// Output results in JSON format, suppressing all other output.
    #[arg(long, short)]
    json: bool,
}

#[derive(Clone)]
struct ScanSettings {
    concurrency: usize,
    timeout: Duration,
}

async fn determine_optimal_settings(ip: IpAddr) -> ScanSettings {
    println!(
        "{}",
        "Probing target to determine optimal settings...".cyan()
    );
    let probe_ports = [80, 443, 22, 53, 3389, 8080, 1337, 31337];
    let mut probe_tasks = FuturesUnordered::new();
    let mut rtts = Vec::new();

    for port in probe_ports {
        let probe_task = tokio::spawn(async move {
            let start = Instant::now();
            let socket_addr = SocketAddr::new(ip, port);
            if timeout(Duration::from_secs(2), TcpStream::connect(&socket_addr))
                .await
                .is_ok()
            {
                return Some(start.elapsed());
            }
            None
        });
        probe_tasks.push(probe_task);
    }

    while let Some(result) = probe_tasks.next().await {
        if let Ok(Some(rtt)) = result {
            rtts.push(rtt);
        }
    }

    if rtts.is_empty() {
        println!(
            "{}",
            "Warning: Target did not respond to probes. Using conservative default settings."
                .yellow()
        );
        return ScanSettings {
            concurrency: 500,
            timeout: Duration::from_millis(3000),
        };
    }

    let avg_rtt: Duration = rtts.iter().sum::<Duration>() / rtts.len() as u32;
    let calculated_timeout = (avg_rtt * 5).saturating_add(Duration::from_millis(400));
    let timeout = calculated_timeout.clamp(Duration::from_millis(500), Duration::from_secs(4));

    let concurrency = if avg_rtt < Duration::from_millis(100) {
        2500
    } else if avg_rtt < Duration::from_millis(250) {
        1800
    } else {
        1000
    };

    #[cfg(unix)]
    let concurrency = {
        let mut concurrency = concurrency;
        if let Ok((soft_limit, _)) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
            let safe_limit = soft_limit.saturating_sub(50) as usize;
            if concurrency > safe_limit {
                println!(
                    "{}",
                    format!(
                        "Warning: Capping concurrency at {} to respect file descriptor limit.",
                        safe_limit
                    )
                    .yellow()
                );
                concurrency = safe_limit;
            }
        }
        concurrency
    };

    let settings = ScanSettings {
        concurrency,
        timeout,
    };
    println!(
        "{}{}{}{}{}",
        "Probe complete. ".green(),
        "Average RTT: ".dimmed(),
        format!("{:?}. ", avg_rtt).bold(),
        "Using: ".dimmed(),
        format!(
            "concurrency={}, timeout={:?}",
            settings.concurrency, settings.timeout
        )
        .bold()
    );
    settings
}

#[tokio::main]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();

    if !args.json {
        println!("{}", ASCII_ART.cyan().bold());
    }

    let settings = match args.timing {
        5 => {
            if !args.json {
                println!("{} {}", "Timing Profile:".bold(), "Insane (-T5)".red());
            }
            ScanSettings {
                concurrency: 5000,
                timeout: Duration::from_millis(300),
            }
        }
        4 => {
            if !args.json {
                println!(
                    "{} {}",
                    "Timing Profile:".bold(),
                    "Aggressive (-T4, auto)".yellow()
                );
            }
            determine_optimal_settings(args.ipaddr).await
        }
        2 => {
            if !args.json {
                println!("{} {}", "Timing Profile:".bold(), "Polite (-T2)".blue());
            }
            ScanSettings {
                concurrency: 400,
                timeout: Duration::from_millis(1200),
            }
        }
        1 => {
            if !args.json {
                println!("{} {}", "Timing Profile:".bold(), "Sneaky (-T1)".dimmed());
            }
            ScanSettings {
                concurrency: 100,
                timeout: Duration::from_secs(5),
            }
        }
        0 => {
            if !args.json {
                println!("{} {}", "Timing Profile:".bold(), "Paranoid (-T0)".dimmed());
            }
            ScanSettings {
                concurrency: 5,
                timeout: Duration::from_secs(15),
            }
        }
        _ => {
            if !args.json {
                println!("{} {}", "Timing Profile:".bold(), "Normal (-T3)".green());
            }
            ScanSettings {
                concurrency: 1000,
                timeout: Duration::from_millis(800),
            }
        }
    };

    let ports_to_scan = match parse_port_spec(&args.ports) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    if !args.json {
        println!(
            "\n{} {} {} {}",
            "Scanning".green(),
            args.ipaddr.to_string().bold(),
            "with".dimmed(),
            format!("{} concurrent tasks...", settings.concurrency).bold()
        );
    }

    let num_ports = ports_to_scan.len() as u64;
    let ip = args.ipaddr;
    let open_ports = Arc::new(Mutex::new(Vec::<(u16, fingerprint::Fingerprint)>::new()));

    // --- Setup The Progress Bar ---
    let pb = if args.json {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(num_ports)
    };

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | ETA: {eta}")
        .unwrap()
        .progress_chars("#>-"));

    let pb_clone = pb.clone();
    let semaphore = Arc::new(Semaphore::new(settings.concurrency));
    let task_open_ports = Arc::clone(&open_ports);
    let task_semaphore = Arc::clone(&semaphore);

    let scan_handle = tokio::spawn(async move {
        stream::iter(ports_to_scan)
            .for_each_concurrent(settings.concurrency, |port| {
                let open_ports_clone = Arc::clone(&task_open_ports);
                let semaphore_clone = Arc::clone(&task_semaphore);
                let pb_clone_inner = pb_clone.clone();

                async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();
                    let socket_addr = SocketAddr::new(ip, port);

                    if let Some(fingerprint) =
                        fingerprint::probe_port(socket_addr, settings.timeout).await
                    {
                        open_ports_clone.lock().unwrap().push((port, fingerprint));
                    }

                    pb_clone_inner.inc(1);
                }
            })
            .await;
    });

    scan_handle.await.unwrap();
    pb.finish_with_message("Scan Complete!");

    let mut final_open_ports = open_ports.lock().unwrap().clone();
    final_open_ports.sort_by_key(|&(p, _)| p);

    if args.json {
        let report = ScanReport {
            target: args.ipaddr.to_string(),
            open_ports: final_open_ports
                .into_iter()
                .map(|(port, fingerprint)| PortReport {
                    port,
                    state: "open",
                    service: fingerprint.service_name,
                    banner: fingerprint.banner,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("\n{:-<80}\n", "");

        if final_open_ports.is_empty() {
            println!("No open ports found.");
        } else {
            println!(
                "{:<10} {:<10} {:<15} {}",
                "PORT".bold(),
                "STATE".bold(),
                "SERVICE".bold(),
                "BANNER".bold()
            );
            println!("{:-<10} {:-<10} {:-<15} {:-<50}", "", "", "", "");

            for (port, fingerprint) in final_open_ports {
                let banner_oneline = fingerprint
                    .banner
                    .replace(['\r', '\n'], " ")
                    .trim()
                    .to_string();
                println!(
                    "{:<10} {:<10} {:<15} {}",
                    format!("{}/tcp", port).yellow(),
                    "open".green(),
                    fingerprint.service_name.blue(),
                    banner_oneline
                );
            }
        }
    }
}

fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "-" {
            ports.extend(1..=65535);
        } else if let Some((start_str, end_str)) = part.split_once('-') {
            let start = start_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid start of range: '{}'", start_str))?;
            let end = end_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid end of range: '{}'", end_str))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("Invalid port range: '{}'.", part));
            }
            ports.extend(start..=end);
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: '{}'", part))?;
            if port == 0 {
                return Err(format!("Invalid port '{}'. Port must be > 0.", part));
            }
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
