//! Raw ICMP echo (ping) support over an unprivileged datagram socket.
//!
//! On Linux, `SOCK_DGRAM` + `IPPROTO_ICMP` lets a process send and receive
//! ICMP echo messages without `CAP_NET_RAW`. The kernel fills in the IP
//! header for us, so we only build and parse the ICMP payload; the source
//! address of a reply is taken from `recvfrom` rather than the packet data.
//!
//! Replies are attributed to a host by their source address and sequence
//! number, not by the identifier field. For `SOCK_DGRAM` sockets the kernel
//! manages the identifier itself and delivers only replies for this socket,
//! so the identifier written into the outgoing request is not reliable for
//! matching.

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Result of a single `recvfrom` on a [`PingSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    /// An ICMP echo reply from `src` for the probe with sequence number `seq`.
    Reply { src: Ipv4Addr, seq: u16 },
    /// A datagram that was not an ICMP echo reply (wrong type or too short).
    Other,
    /// The receive timeout expired with no datagram available.
    Timeout,
}

/// A handle to an unprivileged ICMP datagram socket.
///
/// Replies are matched to a host by the source address (from `recvfrom`) and
/// the sequence number. The identifier written into outgoing requests is
/// informational only: for `SOCK_DGRAM` sockets the kernel manages the reply
/// identifier itself and delivers only this socket's replies, so it is not
/// used for matching.
pub struct PingSocket {
    /// File descriptor of the underlying datagram socket.
    fd: i32,
    /// Identifier written into outgoing echo requests (informational).
    ident: u16,
}

impl PingSocket {
    /// Open a new unprivileged ICMP echo socket.
    ///
    /// Fails with an OS error when the socket cannot be created (for example
    /// when the kernel requires `CAP_NET_RAW` or disables datagram ICMP).
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            ident: std::process::id() as u16,
        })
    }

    /// Send an ICMP echo request to `dest` with sequence number `seq`.
    pub fn send(&self, dest: Ipv4Addr, seq: u16) -> io::Result<()> {
        let mut packet = [0u8; 8];
        packet[0] = 0x08; // type: echo request
        packet[1] = 0x00; // code
        packet[4..6].copy_from_slice(&self.ident.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        let checksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from(dest).to_be();

        let sent = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait up to `timeout` for a single ICMP echo reply.
    ///
    /// The receive timeout is applied per call, so each invocation blocks for
    /// at most `timeout`.
    pub fn recv(&self, timeout: Duration) -> RecvResult {
        let tv = timeval_from_duration(timeout);
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return RecvResult::Other;
        }

        let mut buf = [0u8; 64];
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addrlen,
            )
        };

        if n < 0 {
            return match io::Error::last_os_error().raw_os_error() {
                Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::ETIMEDOUT => {
                    RecvResult::Timeout
                }
                _ => RecvResult::Other,
            };
        }

        if n >= 8 && buf[0] == 0x00 {
            let seq = u16::from_be_bytes([buf[6], buf[7]]);
            let src = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            return RecvResult::Reply { src, seq };
        }
        RecvResult::Other
    }
}

impl Drop for PingSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Compute the ICMP one's-complement checksum over `data`.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Convert a `Duration` into a `libc::timeval` for `SO_RCVTIMEO`.
fn timeval_from_duration(d: Duration) -> libc::timeval {
    let nanos = d.as_nanos();
    libc::timeval {
        tv_sec: (nanos / 1_000_000_000) as libc::time_t,
        tv_usec: ((nanos % 1_000_000_000) / 1_000) as libc::suseconds_t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_vector() {
        // Echo request header: type 8, code 0, checksum 0, ident 0x0001,
        // seq 0x0001. The correct checksum is 0xF7FD.
        let data = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        assert_eq!(icmp_checksum(&data), 0xF7FD);
    }

    #[test]
    fn checksum_handles_odd_length() {
        // A trailing odd byte is padded with a zero high byte.
        let data = [0x00, 0x00, 0x01];
        assert_eq!(icmp_checksum(&data), 0xFEFF);
    }

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        // Recomputing over a packet whose stored checksum is correct must
        // fold back to zero.
        let mut packet = [0u8; 8];
        packet[0] = 0x08;
        packet[4..6].copy_from_slice(&0x0001u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        let csum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(icmp_checksum(&packet), 0);
    }

    #[test]
    fn timeval_converts_milliseconds() {
        let tv = timeval_from_duration(Duration::from_millis(300));
        assert_eq!(tv.tv_sec, 0);
        assert_eq!(tv.tv_usec, 300_000);

        let tv = timeval_from_duration(Duration::from_millis(1500));
        assert_eq!(tv.tv_sec, 1);
        assert_eq!(tv.tv_usec, 500_000);
    }

    #[test]
    fn localhost_round_trip() {
        let socket = match PingSocket::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping localhost round trip: cannot open ICMP socket: {e}");
                return;
            }
        };
        let seq = 0x1234u16;
        if let Err(e) = socket.send(Ipv4Addr::LOCALHOST, seq) {
            eprintln!("skipping localhost round trip: send failed: {e}");
            return;
        }
        for _ in 0..20 {
            match socket.recv(Duration::from_millis(100)) {
                RecvResult::Reply { src, seq: got } if src == Ipv4Addr::LOCALHOST && got == seq => {
                    return;
                }
                RecvResult::Reply { .. } => {
                    // A reply for a different request; keep waiting for ours.
                }
                RecvResult::Timeout | RecvResult::Other => continue,
            }
        }
        panic!("no ICMP reply for 127.0.0.1 (seq {seq:04x}) within timeout");
    }
}
