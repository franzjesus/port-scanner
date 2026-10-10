//! Service detection for open ports.
//!
//! A [`ServiceDetector`] probes a single open port and reports whether it
//! recognizes the service listening there. Detection is best-effort: a
//! detector that fails ([`ServiceError`]) or does not recognize the port
//! (`Ok(None)`) is simply skipped, and the scan never fails because of it.
//!
//! The default detectors recognize HTTP (a plain-text status line), HTTPS
//! (a TLS handshake reply), and SSH (a version banner).

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::network::{Port, ServiceInfo};

/// How long a single service probe (connect plus I/O) may take before it is
/// aborted.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Cap on bytes read from a service probe.
///
/// Banners and status lines are short; capping the read keeps a probe from
/// hanging on a service that trickles bytes.
const MAX_PROBE_BYTES: usize = 8 * 1024;

/// A failure while probing a single port for a service.
///
/// These are expected, normal outcomes of network probing (the service may
/// drop the connection, ignore the probe, or take too long to answer). The
/// scanner treats them as "no service detected" rather than as scan failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The probe failed at the I/O level (connect refused, read error, ...).
    Io(String),
    /// The probe did not complete in time.
    Timeout,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::Io(detail) => write!(f, "service probe I/O failure: {detail}"),
            ServiceError::Timeout => write!(f, "service probe timed out"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// A mechanism for identifying the service listening on a single open port.
///
/// Implementations are shared by reference across the scan and are used from
/// the scanner's background thread, so the trait requires `Send + Sync`.
pub trait ServiceDetector: Send + Sync {
    /// Probe `port` on `ip` and, if this detector recognizes the service
    /// listening there, return its information.
    ///
    /// `Ok(None)` means "this is not the service I detect" — a normal
    /// outcome, not an error. Errors are for probe failures (I/O trouble,
    /// timeouts); the scanner skips the failed detector and moves on.
    fn detect(&self, ip: Ipv4Addr, port: Port) -> Result<Option<ServiceInfo>, ServiceError>;
}

/// Detects an HTTP server by requesting the root path and checking whether
/// the reply starts with an HTTP status line.
pub struct HttpDetector;

impl ServiceDetector for HttpDetector {
    fn detect(&self, ip: Ipv4Addr, port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
        let mut stream = connect(ip, port)?;
        stream
            .set_read_timeout(Some(PROBE_TIMEOUT))
            .map_err(io_error)?;

        let request = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
        stream.write_all(request.as_bytes()).map_err(io_error)?;

        let status_line = read_until_newline(&mut stream, MAX_PROBE_BYTES)?;
        let Some(line) = status_line.lines().next() else {
            return Ok(None);
        };
        if !line.starts_with("HTTP/") {
            return Ok(None);
        }
        let mut info = ServiceInfo::new("http");
        info.extra = Some(line.to_string());
        Ok(Some(info))
    }
}

/// Detects an HTTPS (TLS) server by sending a minimal TLS 1.0 ClientHello
/// and checking whether the reply is a handshake record containing a
/// ServerHello.
pub struct HttpsDetector;

impl ServiceDetector for HttpsDetector {
    fn detect(&self, ip: Ipv4Addr, port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
        let mut stream = connect(ip, port)?;
        stream
            .set_read_timeout(Some(PROBE_TIMEOUT))
            .map_err(io_error)?;
        stream.write_all(&client_hello()).map_err(io_error)?;

        // Five bytes are enough to classify the reply: a handshake record is
        // 0x16 followed by the record version, and the handshake type
        // (ServerHello = 0x02) sits at offset 4.
        let mut data: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        while data.len() < 5 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
                Err(err) => return Err(io_error(err)),
            }
        }
        if data.len() >= 5 && data[0] == 0x16 && data[4] == 0x02 {
            Ok(Some(ServiceInfo::new("https")))
        } else {
            Ok(None)
        }
    }
}

/// Detects an SSH server by reading its version banner (e.g.
/// `SSH-2.0-OpenSSH_9.6p1`) and recording the software token as the version.
pub struct SshDetector;

impl ServiceDetector for SshDetector {
    fn detect(&self, ip: Ipv4Addr, port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
        let mut stream = connect(ip, port)?;
        stream
            .set_read_timeout(Some(PROBE_TIMEOUT))
            .map_err(io_error)?;
        let banner = read_until_newline(&mut stream, 256)?;
        let Some(line) = banner.lines().next() else {
            return Ok(None);
        };
        let rest = match line
            .strip_prefix("SSH-2.0")
            .or_else(|| line.strip_prefix("SSH-1.99"))
        {
            Some(rest) => rest,
            None => return Ok(None),
        };
        let mut info = ServiceInfo::new("ssh");
        if let Some(version) = rest.strip_prefix('-') {
            info.version = Some(version.to_string());
        }
        Ok(Some(info))
    }
}

/// The default set of service detectors, in probe order.
///
/// For a given port the detectors are tried in order and the first one that
/// reports `Some` wins; the rest are not consulted for that port.
pub fn default_detectors() -> Vec<Box<dyn ServiceDetector>> {
    vec![
        Box::new(HttpDetector),
        Box::new(HttpsDetector),
        Box::new(SshDetector),
    ]
}

/// Connect to `ip:port`, bounded by [`PROBE_TIMEOUT`].
fn connect(ip: Ipv4Addr, port: Port) -> Result<TcpStream, ServiceError> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port.as_u16());
    TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).map_err(io_error)
}

/// Translate an I/O error into a [`ServiceError`], mapping timeouts to
/// [`ServiceError::Timeout`].
///
/// Every probe bounds its I/O with a timeout (either [`connect_timeout`] or
/// [`set_read_timeout`]). When such a timeout fires the kernel reports the
/// failure as `WouldBlock` (`EAGAIN`) on Linux but as `TimedOut` on other
/// platforms, so both kinds are treated as a probe timeout here. Because a
/// timeout is always set before a read, a `WouldBlock` in this context can
/// only mean "no data in time".
fn io_error(err: std::io::Error) -> ServiceError {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ServiceError::Timeout,
        _ => ServiceError::Io(err.to_string()),
    }
}

/// Read from `stream` until a newline, EOF, or `max_bytes`, whichever comes
/// first.
fn read_until_newline(stream: &mut TcpStream, max_bytes: usize) -> Result<String, ServiceError> {
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 256];
    while data.len() < max_bytes {
        if data.contains(&b'\n') {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(err) => return Err(io_error(err)),
        }
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Build a minimal TLS 1.0 ClientHello.
///
/// A full TLS stack would generate a random client nonce and negotiate from
/// a wide cipher list, but for *detection* a fixed, spec-valid ClientHello
/// is enough: any conforming TLS server answers with a handshake record, and
/// that answer is what the detector looks for.
fn client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x2b]); // ClientHello, body length 43
    body.extend_from_slice(&[0x03, 0x01]); // client version: TLS 1.0
    body.extend_from_slice(&[0u8; 32]); // random (fixed — not needed for detection)
    body.extend_from_slice(&[0x00]); // session id length: 0
    body.extend_from_slice(&[0x00, 0x02]); // cipher suites length: 2
    body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.extend_from_slice(&[0x01, 0x00]); // compression methods: null
    body.extend_from_slice(&[0x00, 0x00]); // no extensions

    let mut record = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.0
    let len = body.len() as u16;
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(&body);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A detector that never recognizes anything: always `Ok(None)`.
    struct NeverDetector;

    impl ServiceDetector for NeverDetector {
        fn detect(&self, _ip: Ipv4Addr, _port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
            Ok(None)
        }
    }

    /// A detector that always reports a fixed service name.
    struct FixedDetector {
        name: &'static str,
    }

    impl ServiceDetector for FixedDetector {
        fn detect(&self, _ip: Ipv4Addr, _port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
            Ok(Some(ServiceInfo::new(self.name)))
        }
    }

    /// A detector that always fails.
    struct FailingDetector;

    impl ServiceDetector for FailingDetector {
        fn detect(&self, _ip: Ipv4Addr, _port: Port) -> Result<Option<ServiceInfo>, ServiceError> {
            Err(ServiceError::Timeout)
        }
    }

    /// Run `probe` against a local single-connection server.
    ///
    /// `handle` runs on a dedicated thread for the one accepted connection,
    /// so each test can script exactly what the "remote" service says.
    fn with_server(handle: impl Fn(TcpStream) + Send + 'static, probe: impl FnOnce(Port)) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let port = Port::new(listener.local_addr().unwrap().port()).expect("valid port");
        let server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle(stream);
            }
        });
        probe(port);
        let _ = server.join();
    }

    #[test]
    fn detectors_can_be_boxed_and_shared() {
        let detectors: Vec<Box<dyn ServiceDetector>> = vec![Box::new(NeverDetector)];
        let port = Port::new(80).unwrap();
        let result = detectors[0].detect(Ipv4Addr::LOCALHOST, port).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn fixed_detector_reports_its_service() {
        let detector = FixedDetector { name: "http" };
        let port = Port::new(80).unwrap();
        let info = detector.detect(Ipv4Addr::LOCALHOST, port).unwrap().unwrap();
        assert_eq!(info, ServiceInfo::new("http"));
    }

    #[test]
    fn failing_detector_yields_error_not_none() {
        let detector = FailingDetector;
        let port = Port::new(80).unwrap();
        let result = detector.detect(Ipv4Addr::LOCALHOST, port);
        assert_eq!(result, Err(ServiceError::Timeout));
    }

    #[test]
    fn error_display_is_descriptive() {
        assert_eq!(ServiceError::Timeout.to_string(), "service probe timed out");
        assert_eq!(
            ServiceError::Io("refused".to_string()).to_string(),
            "service probe I/O failure: refused"
        );
    }

    #[test]
    fn http_detector_reads_the_status_line() {
        with_server(
            |mut stream| {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
            },
            |port| {
                let info = HttpDetector
                    .detect(Ipv4Addr::LOCALHOST, port)
                    .unwrap()
                    .expect("should recognize the fake HTTP server");
                assert_eq!(info.name, "http");
                assert_eq!(info.extra.as_deref(), Some("HTTP/1.0 200 OK"));
                assert_eq!(info.version, None);
            },
        );
    }

    #[test]
    fn http_detector_rejects_a_non_http_reply() {
        with_server(
            |mut stream| {
                let _ = stream.write_all(b"220 fake-banner\r\n");
            },
            |port| {
                let result = HttpDetector.detect(Ipv4Addr::LOCALHOST, port).unwrap();
                assert_eq!(result, None);
            },
        );
    }

    #[test]
    fn https_detector_recognizes_a_tls_handshake_reply() {
        // A minimal ServerHello-shaped reply: handshake record (0x16), record
        // version, record length, handshake type 0x02 (ServerHello).
        with_server(
            |mut stream| {
                let _ = stream.write_all(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00]);
            },
            |port| {
                let info = HttpsDetector
                    .detect(Ipv4Addr::LOCALHOST, port)
                    .unwrap()
                    .expect("should recognize the fake TLS server");
                assert_eq!(info.name, "https");
            },
        );
    }

    #[test]
    fn https_detector_rejects_a_non_tls_reply() {
        with_server(
            |mut stream| {
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n");
            },
            |port| {
                let result = HttpsDetector.detect(Ipv4Addr::LOCALHOST, port).unwrap();
                assert_eq!(result, None);
            },
        );
    }

    #[test]
    fn ssh_detector_reads_the_banner_version() {
        with_server(
            |mut stream| {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n");
            },
            |port| {
                let info = SshDetector
                    .detect(Ipv4Addr::LOCALHOST, port)
                    .unwrap()
                    .expect("should recognize the fake SSH server");
                assert_eq!(info.name, "ssh");
                assert_eq!(info.version.as_deref(), Some("OpenSSH_9.6p1"));
                assert_eq!(info.extra, None);
            },
        );
    }

    #[test]
    fn ssh_detector_rejects_a_non_ssh_banner() {
        with_server(
            |mut stream| {
                let _ = stream.write_all(b"220 fake-banner\r\n");
            },
            |port| {
                let result = SshDetector.detect(Ipv4Addr::LOCALHOST, port).unwrap();
                assert_eq!(result, None);
            },
        );
    }

    /// A service that accepts the connection but never answers must produce
    /// a timeout error, not a hang. Takes ~`PROBE_TIMEOUT`.
    #[test]
    fn unresponsive_service_times_out() {
        with_server(
            // Hold the connection open without sending anything so the probe
            // blocks on its read until the timeout fires.
            |_stream| {
                thread::sleep(Duration::from_millis(3000));
            },
            |port| {
                let result = HttpDetector.detect(Ipv4Addr::LOCALHOST, port);
                assert_eq!(result, Err(ServiceError::Timeout));
            },
        );
    }

    #[test]
    fn client_hello_is_a_valid_tls10_handshake_record() {
        let hello = client_hello();
        assert_eq!(hello[0], 0x16); // handshake record
        assert_eq!(&hello[1..3], &[0x03, 0x01]); // TLS 1.0
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], 0x01); // ClientHello
        let body_len =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | (hello[8] as usize);
        assert_eq!(4 + body_len, record_len);
        assert_eq!(&hello[9..11], &[0x03, 0x01]); // client version: TLS 1.0
    }

    #[test]
    fn default_detectors_provide_the_builtin_set() {
        let detectors = default_detectors();
        assert_eq!(detectors.len(), 3);
    }
}
