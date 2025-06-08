use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    self, ClientConfig,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
const READ_BUFFER_SIZE: usize = 2048;
const BANNER_TIMEOUT: Duration = Duration::from_secs(4);

// --- START: Corrected Regex-based matching engine ---

struct Matcher {
    service: &'static str,
    // The struct now holds a *reference* to a static Lazy<Regex>.
    regex: &'static Lazy<Regex>,
}

// Step 1: Each Lazy<Regex> is defined as its own static item.
static SSH_MATCHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^SSH-2.0-([^\s]+)").unwrap());
static HTTP_SERVER_MATCHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"Server: ([^\r\n]+)").unwrap());
static HTTP_GENERIC_MATCHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"HTTP/\d\.\d").unwrap());
static FTP_MATCHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^220 .*FTP").unwrap());
static SMTP_MATCHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^220 .*SMTP").unwrap());

// Step 2: The MATCHERS array now holds references to the statics above.
static MATCHERS: &[Matcher] = &[
    Matcher {
        service: "ssh",
        regex: &SSH_MATCHER,
    },
    Matcher {
        service: "http",
        regex: &HTTP_SERVER_MATCHER,
    },
    Matcher {
        service: "http",
        regex: &HTTP_GENERIC_MATCHER,
    },
    Matcher {
        service: "ftp",
        regex: &FTP_MATCHER,
    },
    Matcher {
        service: "smtp",
        regex: &SMTP_MATCHER,
    },
];

// --- END: Corrected Regex-based matching engine ---

#[derive(Debug)]
struct InsecureCertificateVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertificateVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Probe {
    _name: &'static str,
    payload: &'static [u8],
    ports: &'static [u16],
}

const PROBES: &[Probe] = &[
    Probe {
        _name: "SMB",
        payload: b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x53\x41\x4d\x42\x41\x00\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00",
        ports: &[139, 445],
    },
    Probe {
        _name: "RDP",
        payload: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        ports: &[3389],
    },
    Probe {
        _name: "HTTP",
        payload: b"GET / HTTP/1.0\r\n\r\n",
        ports: &[80, 8000, 8080, 9993],
    },
    Probe {
        _name: "Generic-Newline",
        payload: b"\r\n\r\n",
        ports: &[],
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct Fingerprint {
    pub service_name: String,
    pub banner: String,
}

pub async fn probe_port(addr: SocketAddr, connect_timeout: Duration) -> Option<Fingerprint> {
    let stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => return None,
    };
    match addr.port() {
        443 | 993 | 995 => probe_tls(stream).await,
        _ => probe_cleartext(stream).await,
    }
}

async fn probe_tls(stream: TcpStream) -> Option<Fingerprint> {
    let addr = stream.peer_addr().ok()?;
    let port = addr.port();
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertificateVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from("localhost").unwrap();
    if let Ok(Ok(mut tls_stream)) = timeout(BANNER_TIMEOUT, connector.connect(domain, stream)).await
    {
        if port == 443 {
            let _ = tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
        }
        let response_bytes = read_from_stream(&mut tls_stream).await.unwrap_or_default();
        return Some(analyze_response(&response_bytes, port));
    }
    Some(Fingerprint {
        service_name: "tls".to_string(),
        banner: "Could not complete TLS handshake".to_string(),
    })
}

async fn probe_cleartext(mut stream: TcpStream) -> Option<Fingerprint> {
    let addr = stream.peer_addr().ok()?;
    let port = addr.port();
    if let Some(response_bytes) = read_from_stream(&mut stream).await {
        if !response_bytes.is_empty() {
            return Some(analyze_response(&response_bytes, port));
        }
    }
    let applicable_probes = PROBES.iter().filter(|p| p.ports.contains(&port));
    for probe in applicable_probes {
        if stream.write_all(probe.payload).await.is_ok() {
            if let Some(response_bytes) = read_from_stream(&mut stream).await {
                return Some(analyze_response(&response_bytes, port));
            }
        }
    }
    let fallback_probes = PROBES.iter().filter(|p| p.ports.is_empty());
    for probe in fallback_probes {
        if stream.write_all(probe.payload).await.is_ok() {
            if let Some(response_bytes) = read_from_stream(&mut stream).await {
                return Some(analyze_response(&response_bytes, port));
            }
        }
    }
    Some(Fingerprint {
        service_name: get_service_name_from_port(port).to_string(),
        banner: "[unresponsive]".to_string(),
    })
}

async fn read_from_stream<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buffer = vec![0; READ_BUFFER_SIZE];
    match timeout(BANNER_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(bytes_read)) if bytes_read > 0 => {
            buffer.truncate(bytes_read);
            Some(buffer)
        }
        _ => None,
    }
}

fn analyze_response(response_bytes: &[u8], port: u16) -> Fingerprint {
    if [139, 445].contains(&port)
        && response_bytes.starts_with(&[0x00, 0x00])
        && response_bytes.windows(4).any(|window| window == b"\xFFSMB")
    {
        return Fingerprint {
            service_name: "smb".to_string(),
            banner: format!(
                "[SMB Response: {} bytes] {}",
                response_bytes.len(),
                to_hex_string(response_bytes)
            ),
        };
    }
    match std::str::from_utf8(response_bytes) {
        Ok(banner_str) => analyze_text_banner(banner_str, port),
        Err(_) => {
            let service_name = get_service_name_from_port(port).to_string();
            let banner = format!(
                "[Binary data: {} bytes] {}",
                response_bytes.len(),
                to_hex_string(response_bytes)
            );
            Fingerprint {
                service_name,
                banner,
            }
        }
    }
}

fn analyze_text_banner(banner: &str, port: u16) -> Fingerprint {
    let banner_trimmed = banner.trim();

    for matcher in MATCHERS {
        if let Some(captures) = matcher.regex.captures(banner) {
            let info = captures.get(1).map_or("", |m| m.as_str()).trim();

            return Fingerprint {
                service_name: matcher.service.to_string(),
                banner: if info.is_empty() {
                    banner.lines().next().unwrap_or("").to_string()
                } else {
                    info.to_string()
                },
            };
        }
    }

    Fingerprint {
        service_name: get_service_name_from_port(port).to_string(),
        banner: banner_trimmed.lines().next().unwrap_or("").to_string(),
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    const MAX_HEX_BYTES: usize = 24;
    let mut hex_str = String::new();
    for byte in bytes.iter().take(MAX_HEX_BYTES) {
        hex_str.push_str(&format!("{:02X} ", byte));
    }
    if bytes.len() > MAX_HEX_BYTES {
        hex_str.push_str("...");
    }
    hex_str.trim_end().to_string()
}

fn get_service_name_from_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        6379 => "redis",
        27017 => "mongodb",
        _ => "unknown",
    }
}
