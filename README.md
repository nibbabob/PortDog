# PortDog 🐶

```
 ____            _     ____              
|  _ \ ___  _ __| |_  |  _ \  ___   __ _ 
| |_) / _ \| '__| __| | | | |/ _ \ / _` |
|  __/ (_) | |  | |_  | |_| | (_) | (_| |
|_|   \___/|_|   \__| |____/ \___/ \__, |
                                  |___/ 
```

**A lightning-fast port scanner with a nose for open ports, built in Rust.**

[![Rust Version](https://img.shields.io/badge/Rust-1.80%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/nibbabob/PortDog/rust.yml?branch=main&style=for-the-badge)](https://github.com/nibbabob/PortDog/actions)

---

PortDog isn't just another port scanner. It's a demonstration of modern, high-performance network programming in Rust, built from the ground up to be fast, accurate, and intelligent. It uses an asynchronous `tokio` runtime to handle thousands of concurrent connections and features a sophisticated, multi-stage fingerprinting engine to identify services with precision.

## ✨ Features

* **Blazingly Fast:** Asynchronous, concurrent scanning engine capable of checking thousands of ports per second.
* **Adaptive Timing:** Automatically tunes scan speed and timeouts based on network latency (`-T4`), with multiple timing templates (`-T0` to `-T5`) for full control over the speed vs. reliability trade-off.
* **Advanced Fingerprinting:** Goes beyond simple banner grabs with protocol-specific active probes for services like HTTP, SMB, and RDP.
* **Intelligent Analysis:** Uses a regex-based matching engine to accurately identify services and extract version information.
* **TLS/HTTPS Scanning:** Successfully fingerprints services behind TLS by accepting self-signed or invalid certificates.
* **Versatile Output:** Choose between a beautiful, colorized, human-readable table or structured JSON output for easy integration with other tools.
* **Polished User Experience:** Features a dynamic progress bar, a memorable ASCII art logo, and a helpful command-line interface.

## 🚀 Demo

Here's a look at PortDog performing an aggressive scan. A live animated progress bar is shown in the terminal during the scan itself.

**Command:**
```sh
./target/release/portdog scanme.nmap.org -p- -T4
```

**Output:**
```text
 ____            _     ____
|  _ \ ___  _ __| |_  |  _ \  ___   __ _
| |_) / _ \| '__| __| | | | |/ _ \ / _` |
|  __/ (_) | |  | |_  | |_| | (_) | (_| |
|_|   \___/|_|   \__| |____/ \___/ \__, |
                                  |___/
A lightning-fast port scanner with a nose for open ports.

Timing Profile: Aggressive (-T4, auto)
Probing target to determine optimal settings...
Probe complete. Average RTT: 48.1ms. Using: concurrency=2500, timeout=640ms

Scanning scanme.nmap.org with 2500 concurrent tasks...
✔ Scan Complete!

--------------------------------------------------------------------------------

PORT       STATE      SERVICE         BANNER
---------- ---------- --------------- --------------------------------------------------
22/tcp     open       ssh             OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp     open       http            nginx/1.4.6 (Ubuntu)
443/tcp    open       http            nginx/1.4.6 (Ubuntu)
9929/tcp   open       nping-echo      Nping-echo service -- Nping is a tool from Nmap
31337/tcp  open       unknown         [unresponsive]
```

## 🛠️ Building From Source

### Prerequisites
* [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
* [Git](https://git-scm.com/)

### Build Steps

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/nibbabob/PortDog.git](https://github.com/nibbabob/PortDog.git)
    cd PortDog
    ```

2.  **Build the optimized release executable:**
    ```sh
    cargo build --release
    ```

3.  **Run PortDog:**
    The final binary will be located at `./target/release/portdog`. You can run it from there or move it to a directory in your system's PATH for global access.

## 📖 Usage

```sh
# Display the help menu
./target/release/portdog --help
```
```text
PortDog: A lightning-fast asynchronous port scanner with adaptive timing and fingerprinting.

Usage: portdog.exe [OPTIONS] <IPADDR>

Arguments:
  <IPADDR>
          The IP address to scan

Options:
  -p, --ports <PORTS>
          Ports to scan. Ex: 80,443 | 1-1024 | -
          [default: 1-1024]

  -T, --timing <TIMING>
          Set timing template (0-5, default: 3). Higher is faster and more aggressive
          [default: 3]
          [possible values: 0, 1, 2, 3, 4, 5]

  -j, --json
          Output results in JSON format, suppressing all other output

  -h, --help
          Print help

  -V, --version
          Print version
```

### Examples

**1. A quick, reliable scan of common ports on a host:**
```sh
./target/release/portdog scanme.nmap.org
```

**2. An aggressive, all-ports scan with auto-tuned timing:**
```sh
./target/release/portdog 192.168.1.1 -p- -T4
```

**3. A slow, polite scan for a specific list of ports:**
```sh
./target/release/portdog example.com -p 21,22,80,443,8080 -T2
```

**4. Scan all ports and pipe the results to `jq` for processing:**
```sh
./target/release/portdog 10.0.0.1 -p- --json | jq .
```

## 📜 License

This project is licensed under the **MIT License**.
