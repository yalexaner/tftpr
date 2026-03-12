use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::packet::{self, Packet};

/// resolves the real filesystem path of an open file descriptor.
#[cfg(unix)]
fn fd_real_path(fd: std::os::unix::io::RawFd) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let ret = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(PathBuf::from(std::ffi::OsString::from_vec(
            buf[..len].to_vec(),
        )))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fd-to-path not supported on this platform",
        ))
    }
}

/// verifies that an opened file descriptor actually resides within the
/// expected root directory. closes the TOCTOU gap between path resolution
/// and file open by reading the real path from the fd.
#[cfg(unix)]
fn verify_fd_within_root(file: &File, root: &Path) -> Result<(), Packet> {
    use std::os::unix::io::AsRawFd;

    let canonical_root = root.canonicalize().map_err(|_| Packet::Error {
        code: packet::ERR_NOT_DEFINED,
        message: "server error".into(),
    })?;

    let real_path = match fd_real_path(file.as_raw_fd()) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
        Err(_) => {
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "server error".into(),
            });
        }
    };

    if !real_path.starts_with(&canonical_root) {
        return Err(Packet::Error {
            code: packet::ERR_ACCESS_VIOLATION,
            message: "access violation".into(),
        });
    }

    Ok(())
}

const MAX_RETRIES: u32 = 3;
const RETRY_TIMEOUT: Duration = Duration::from_secs(5);

pub const DEFAULT_BLOCK_SIZE: usize = 512;
pub const MAX_BLOCK_SIZE: usize = 65464;

// compile-time guarantee that MAX_BLOCK_SIZE fits in u16 (used for OACK encoding)
const _: () = assert!(MAX_BLOCK_SIZE <= u16::MAX as usize);

/// reads the blksize option from the typed Options struct and caps at
/// server_max. returns None if blksize is absent, below 512, or if the
/// negotiated value equals the default 512 (sending OACK for the standard
/// block size adds overhead with no benefit).
pub fn negotiate_blksize(options: &packet::Options, server_max: usize) -> Option<usize> {
    options
        .blksize
        .map(|v| v as usize)
        .filter(|&requested| requested >= DEFAULT_BLOCK_SIZE)
        .map(|requested| requested.min(server_max))
        .filter(|&negotiated| negotiated > DEFAULT_BLOCK_SIZE)
}

/// resolves the requested filename against the root directory.
/// rejects path traversal attempts by ensuring the resolved path
/// stays within root.
fn resolve_path(root: &Path, filename: &str) -> Result<PathBuf, Packet> {
    let requested = Path::new(filename);

    // reject absolute paths and any component that is ".."
    if requested.is_absolute() {
        return Err(Packet::Error {
            code: packet::ERR_ACCESS_VIOLATION,
            message: "access violation".into(),
        });
    }

    for component in requested.components() {
        if let std::path::Component::ParentDir = component {
            return Err(Packet::Error {
                code: packet::ERR_ACCESS_VIOLATION,
                message: "access violation".into(),
            });
        }
    }

    let full_path = root.join(requested);

    // final safety check: canonicalize and verify prefix
    let canonical = full_path.canonicalize().map_err(|_| Packet::Error {
        code: packet::ERR_FILE_NOT_FOUND,
        message: "file not found".into(),
    })?;

    let canonical_root = root.canonicalize().map_err(|_| Packet::Error {
        code: packet::ERR_FILE_NOT_FOUND,
        message: "file not found".into(),
    })?;

    if !canonical.starts_with(&canonical_root) {
        return Err(Packet::Error {
            code: packet::ERR_ACCESS_VIOLATION,
            message: "access violation".into(),
        });
    }

    Ok(canonical)
}

/// resolves the requested filename for a write operation.
/// rejects path traversal and absolute paths, and rejects files that already exist.
fn resolve_path_for_write(root: &Path, filename: &str) -> Result<PathBuf, Packet> {
    let requested = Path::new(filename);

    if requested.is_absolute() {
        return Err(Packet::Error {
            code: packet::ERR_ACCESS_VIOLATION,
            message: "access violation".into(),
        });
    }

    for component in requested.components() {
        if let std::path::Component::ParentDir = component {
            return Err(Packet::Error {
                code: packet::ERR_ACCESS_VIOLATION,
                message: "access violation".into(),
            });
        }
    }

    let canonical_root = root.canonicalize().map_err(|_| Packet::Error {
        code: packet::ERR_NOT_DEFINED,
        message: "server error".into(),
    })?;

    let full_path = canonical_root.join(requested);

    // reject symlinks at the target path to prevent writing outside root
    if full_path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(Packet::Error {
            code: packet::ERR_ACCESS_VIOLATION,
            message: "access violation".into(),
        });
    }

    // verify resolved path stays within root
    // normalize by checking that the parent dir is within root
    if let Some(parent) = full_path.parent() {
        if parent.exists() {
            let canonical_parent = parent.canonicalize().map_err(|_| Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "server error".into(),
            })?;
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(Packet::Error {
                    code: packet::ERR_ACCESS_VIOLATION,
                    message: "access violation".into(),
                });
            }
        } else {
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "parent directory does not exist".into(),
            });
        }
    }

    Ok(full_path)
}

/// handles a read request: sends the file to the peer in DATA blocks.
/// when negotiated_blksize is Some, sends an OACK first and waits for
/// ACK(0) before transmitting data.
pub async fn handle_rrq(
    root: &Path,
    socket: &UdpSocket,
    filename: &str,
    negotiated_blksize: Option<usize>,
) -> Result<(), Packet> {
    let path = resolve_path(root, filename)?;

    let mut file = File::open(&path).await.map_err(|e| {
        let (code, message) = match e.kind() {
            std::io::ErrorKind::NotFound => (packet::ERR_FILE_NOT_FOUND, "file not found"),
            std::io::ErrorKind::PermissionDenied => {
                (packet::ERR_ACCESS_VIOLATION, "access violation")
            }
            _ => (packet::ERR_NOT_DEFINED, "read error"),
        };
        Packet::Error {
            code,
            message: message.into(),
        }
    })?;

    // verify the opened fd is actually within root (closes TOCTOU gap)
    #[cfg(unix)]
    verify_fd_within_root(&file, root)?;

    let block_size = negotiated_blksize.unwrap_or(DEFAULT_BLOCK_SIZE);

    // send OACK if blksize was negotiated, then wait for ACK(0)
    if negotiated_blksize.is_some() {
        let oack = Packet::Oack {
            options: packet::Options {
                blksize: Some(block_size as u16),
            },
        };
        let encoded = oack.encode();

        let mut timeouts = 0u32;
        loop {
            if socket.send(&encoded).await.is_err() {
                timeouts += 1;
                if timeouts >= MAX_RETRIES {
                    return Err(Packet::Error {
                        code: packet::ERR_NOT_DEFINED,
                        message: "transfer timed out".into(),
                    });
                }
                continue;
            }

            match wait_for_ack(socket, 0).await {
                Ok(()) => break,
                Err(true) => return Ok(()),
                Err(false) => {
                    timeouts += 1;
                    if timeouts >= MAX_RETRIES {
                        return Err(Packet::Error {
                            code: packet::ERR_NOT_DEFINED,
                            message: "transfer timed out".into(),
                        });
                    }
                    continue;
                }
            }
        }
    }

    let mut block_num: u16 = 1;
    let mut buf = vec![0u8; block_size];

    loop {
        let mut bytes_read = 0;
        while bytes_read < block_size {
            let n = file
                .read(&mut buf[bytes_read..])
                .await
                .map_err(|_| Packet::Error {
                    code: packet::ERR_NOT_DEFINED,
                    message: "read error".into(),
                })?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        let data_pkt = Packet::Data {
            block_num,
            data: buf[..bytes_read].to_vec(),
        };
        let encoded = data_pkt.encode();

        // send and wait for ACK with retries (only count timeouts, not stale ACKs)
        let mut acked = false;
        let mut client_error = false;
        let mut timeouts = 0u32;
        loop {
            if socket.send(&encoded).await.is_err() {
                timeouts += 1;
                if timeouts >= MAX_RETRIES {
                    break;
                }
                continue;
            }

            match wait_for_ack(socket, block_num).await {
                Ok(()) => {
                    acked = true;
                    break;
                }
                Err(true) => {
                    client_error = true;
                    break;
                }
                Err(false) => {
                    timeouts += 1;
                    if timeouts >= MAX_RETRIES {
                        break;
                    }
                    continue;
                }
            }
        }

        if client_error {
            // client sent ERROR - don't respond per RFC 1350 Section 5
            return Ok(());
        }

        if !acked {
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "transfer timed out".into(),
            });
        }

        // last block: data smaller than block_size signals end of transfer
        if bytes_read < block_size {
            break;
        }

        if block_num == u16::MAX {
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "file too large for TFTP".into(),
            });
        }
        block_num += 1;
    }

    Ok(())
}

/// handles a write request: receives the file from the peer in DATA blocks.
/// when negotiated_blksize is Some, sends an OACK instead of ACK(0) and
/// waits for DATA(1) as confirmation (per RFC 2347).
pub async fn handle_wrq(
    root: &Path,
    socket: &UdpSocket,
    filename: &str,
    negotiated_blksize: Option<usize>,
) -> Result<(), Packet> {
    let path = resolve_path_for_write(root, filename)?;

    // create file atomically before accepting the transfer
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .map_err(|e| {
            let (code, message) = match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    (packet::ERR_FILE_EXISTS, "file already exists")
                }
                std::io::ErrorKind::PermissionDenied => {
                    (packet::ERR_ACCESS_VIOLATION, "access violation")
                }
                _ => (packet::ERR_DISK_FULL, "cannot create file"),
            };
            Packet::Error {
                code,
                message: message.into(),
            }
        })?;

    // verify the created file is actually within root (closes TOCTOU gap).
    // on failure, we intentionally do NOT remove by pathname — the path
    // is untrustworthy at this point (symlink swap between verify and
    // unlink would allow arbitrary file deletion). a leaked empty file
    // is the lesser evil.
    #[cfg(unix)]
    if let Err(e) = verify_fd_within_root(&file, root) {
        drop(file);
        return Err(e);
    }

    let block_size = negotiated_blksize.unwrap_or(DEFAULT_BLOCK_SIZE);

    // per RFC 2347, OACK for WRQ is acknowledged by DATA(1), not ACK(0)
    let mut first_data: Option<Vec<u8>> = None;

    if negotiated_blksize.is_some() {
        let oack = Packet::Oack {
            options: packet::Options {
                blksize: Some(block_size as u16),
            },
        };
        let oack_bytes = oack.encode();

        socket.send(&oack_bytes).await.map_err(|_| Packet::Error {
            code: packet::ERR_NOT_DEFINED,
            message: "failed to send OACK".into(),
        })?;

        // wait for DATA(1) with OACK retransmission on timeout
        match wait_for_data(socket, 1, block_size, Some(&oack_bytes)).await {
            Ok(data) => first_data = Some(data),
            Err(true) => {
                // client rejected OACK — intentionally do NOT remove by
                // pathname (same TOCTOU concern as the verify_fd failure
                // path above). a leaked empty file is the lesser evil.
                drop(file);
                return Ok(());
            }
            Err(false) => {
                drop(file);
                return Err(Packet::Error {
                    code: packet::ERR_NOT_DEFINED,
                    message: "transfer timed out".into(),
                });
            }
        }
    } else {
        // send ACK 0 to accept the transfer
        let ack0 = Packet::Ack { block_num: 0 };
        socket
            .send(&ack0.encode())
            .await
            .map_err(|_| Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "failed to send initial ACK".into(),
            })?;
    }

    let mut expected_block: u16 = 1;

    loop {
        // use pre-received DATA(1) from OACK handshake if available
        let data = if let Some(d) = first_data.take() {
            d
        } else {
            match wait_for_data(socket, expected_block, block_size, None).await {
                Ok(d) => d,
                Err(client_error) => {
                    if client_error {
                        // client sent ERROR - don't respond per RFC 1350 Section 5
                        return Ok(());
                    }
                    return Err(Packet::Error {
                        code: packet::ERR_NOT_DEFINED,
                        message: "transfer timed out".into(),
                    });
                }
            }
        };

        // write data to file
        file.write_all(&data).await.map_err(|_| Packet::Error {
            code: packet::ERR_DISK_FULL,
            message: "disk write failed".into(),
        })?;

        // send ACK for this block
        let ack = Packet::Ack {
            block_num: expected_block,
        };
        if let Err(e) = socket.send(&ack.encode()).await {
            eprintln!("failed to send ACK for block {expected_block}: {e}");
        }

        // last block: data smaller than block_size signals end of transfer
        if data.len() < block_size {
            break;
        }

        if expected_block == u16::MAX {
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "file too large for TFTP".into(),
            });
        }
        expected_block += 1;
    }

    file.flush().await.map_err(|_| Packet::Error {
        code: packet::ERR_DISK_FULL,
        message: "disk write failed".into(),
    })?;

    Ok(())
}

/// waits for a DATA packet with the expected block number, with retries and timeout.
/// uses a total deadline so stale/wrong packets cannot extend the wait indefinitely.
/// returns Ok(data) on success, Err(true) if client sent ERROR (fatal),
/// Err(false) on timeout after retries.
async fn wait_for_data(
    socket: &UdpSocket,
    expected_block: u16,
    block_size: usize,
    on_timeout_send: Option<&[u8]>,
) -> Result<Vec<u8>, bool> {
    let deadline = tokio::time::Instant::now() + RETRY_TIMEOUT * MAX_RETRIES;
    let mut next_resend = tokio::time::Instant::now() + RETRY_TIMEOUT;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(false);
        }

        let wait_until = next_resend.min(deadline);
        let remaining = wait_until.saturating_duration_since(now);

        // allocate 1 extra byte to detect oversized datagrams — UDP recv()
        // silently truncates, so without this we'd write corrupt data
        let mut recv_buf = vec![0u8; 4 + block_size + 1];
        let result = tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await;

        match result {
            Ok(Ok(len)) if len > 4 + block_size => {
                // oversized packet, skip it
            }
            Ok(Ok(len)) => match Packet::decode(&recv_buf[..len]) {
                Ok(Packet::Data { block_num, data }) if block_num == expected_block => {
                    return Ok(data);
                }
                Ok(Packet::Data { block_num, .. })
                    if block_num == expected_block.wrapping_sub(1) =>
                {
                    // client retransmitted previous block (likely lost ACK) - re-ACK it
                    let ack = Packet::Ack { block_num };
                    let _ = socket.send(&ack.encode()).await;
                }
                Ok(Packet::Error { .. }) => return Err(true),
                _ => {
                    // other wrong block or non-DATA packet - ignored, deadline still applies
                }
            },
            _ => {
                // timeout or recv error - retransmit to trigger client resend
                if let Some(bytes) = on_timeout_send {
                    let _ = socket.send(bytes).await;
                } else {
                    let prev_ack = Packet::Ack {
                        block_num: expected_block.wrapping_sub(1),
                    };
                    let _ = socket.send(&prev_ack.encode()).await;
                }
                next_resend = tokio::time::Instant::now() + RETRY_TIMEOUT;
            }
        }
    }
}

/// waits for an ACK with the expected block number, with timeout.
/// drains stale/wrong-block ACKs without counting them as retries.
/// returns Ok(()) on success, Err(true) if client sent ERROR (fatal),
/// Err(false) on timeout (retryable).
async fn wait_for_ack(socket: &UdpSocket, expected_block: u16) -> Result<(), bool> {
    let deadline = tokio::time::Instant::now() + RETRY_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(false);
        }

        let mut recv_buf = [0u8; 512];
        let len = tokio::time::timeout(remaining, socket.recv(&mut recv_buf))
            .await
            .map_err(|_| false)?
            .map_err(|_| false)?;

        match Packet::decode(&recv_buf[..len]) {
            Ok(Packet::Ack { block_num }) if block_num == expected_block => return Ok(()),
            Ok(Packet::Error { .. }) => return Err(true),
            _ => continue, // stale/wrong-block ACK, keep waiting
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    /// helper: creates a temp dir with a file, returns (root_path, server_socket, client_socket)
    async fn setup(filename: &str, content: &[u8]) -> (tempfile::TempDir, UdpSocket, UdpSocket) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(filename), content).unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        server_sock.connect(client_addr).await.unwrap();
        client_sock.connect(server_addr).await.unwrap();

        (dir, server_sock, client_sock)
    }

    #[test]
    fn resolve_path_normal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hi").unwrap();
        let result = resolve_path(dir.path(), "hello.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_path_traversal_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path(dir.path(), "../etc/passwd");
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[test]
    fn resolve_path_absolute_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path(dir.path(), "/etc/passwd");
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[test]
    fn resolve_path_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path(dir.path(), "nonexistent.txt");
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_FILE_NOT_FOUND);
    }

    #[tokio::test]
    async fn successful_small_file_transfer() {
        let content = b"hello, tftp!";
        let (dir, server_sock, client_sock) = setup("small.txt", content).await;

        let root = dir.path().to_path_buf();
        let handle =
            tokio::spawn(async move { handle_rrq(&root, &server_sock, "small.txt", None).await });

        // receive DATA block 1
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Data { block_num, data } => {
                assert_eq!(*block_num, 1);
                assert_eq!(data, content);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // send ACK
        let ack = Packet::Ack { block_num: 1 };
        client_sock.send(&ack.encode()).await.unwrap();

        // handler should complete successfully
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn successful_multi_block_transfer() {
        // 512 bytes = exactly one full block, so we need a second (empty) block to signal end
        let content = vec![0xAB; 512];
        let (dir, server_sock, client_sock) = setup("multi.bin", &content).await;

        let root = dir.path().to_path_buf();
        let handle =
            tokio::spawn(async move { handle_rrq(&root, &server_sock, "multi.bin", None).await });

        let mut received = Vec::new();

        for expected_block in 1..=2 {
            let mut buf = [0u8; 600];
            let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();

            let pkt = Packet::decode(&buf[..len]).unwrap();
            match &pkt {
                Packet::Data { block_num, data } => {
                    assert_eq!(*block_num, expected_block);
                    received.extend_from_slice(data);
                }
                other => panic!("expected Data block {expected_block}, got {other:?}"),
            }

            let ack = Packet::Ack {
                block_num: expected_block,
            };
            client_sock.send(&ack.encode()).await.unwrap();
        }

        assert_eq!(received, content);

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn file_not_found_error() {
        let dir = tempfile::tempdir().unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        server_sock.connect(client_addr).await.unwrap();
        client_sock
            .connect(server_sock.local_addr().unwrap())
            .await
            .unwrap();

        let root = dir.path().to_path_buf();
        let result = handle_rrq(&root, &server_sock, "nope.txt", None).await;
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_FILE_NOT_FOUND);
    }

    #[tokio::test]
    async fn path_traversal_rejected_in_handler() {
        let dir = tempfile::tempdir().unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        server_sock.connect(client_addr).await.unwrap();
        client_sock
            .connect(server_sock.local_addr().unwrap())
            .await
            .unwrap();

        let root = dir.path().to_path_buf();
        let result = handle_rrq(&root, &server_sock, "../etc/passwd", None).await;
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[tokio::test]
    async fn timeout_after_retries() {
        let content = b"timeout test";
        let (dir, server_sock, _client_sock) = setup("timeout.txt", content).await;

        // client never sends ACK, so server should time out after retries
        let root = dir.path().to_path_buf();

        // use a short timeout for testing by calling internal logic directly
        // but since we use the constant, this test will take MAX_RETRIES * RETRY_TIMEOUT
        // instead, we test the mechanism by dropping the client socket
        // the server will fail to receive ACK and eventually give up
        drop(_client_sock);

        let result = tokio::time::timeout(
            Duration::from_secs(MAX_RETRIES as u64 * RETRY_TIMEOUT.as_secs() + 5),
            handle_rrq(&root, &server_sock, "timeout.txt", None),
        )
        .await
        .unwrap();

        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_NOT_DEFINED);
        assert!(message.contains("timed out"));
    }

    // --- WRQ tests ---

    /// helper: creates a temp dir (empty), returns (root_path, server_socket, client_socket)
    async fn setup_wrq() -> (tempfile::TempDir, UdpSocket, UdpSocket) {
        let dir = tempfile::tempdir().unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        server_sock.connect(client_addr).await.unwrap();
        client_sock.connect(server_addr).await.unwrap();

        (dir, server_sock, client_sock)
    }

    #[tokio::test]
    async fn wrq_successful_small_upload() {
        let (dir, server_sock, client_sock) = setup_wrq().await;
        let content = b"hello upload!";

        let root = dir.path().to_path_buf();
        let handle =
            tokio::spawn(
                async move { handle_wrq(&root, &server_sock, "uploaded.txt", None).await },
            );

        // receive ACK 0
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(pkt, Packet::Ack { block_num: 0 });

        // send DATA block 1 (< 512 bytes = last block)
        let data_pkt = Packet::Data {
            block_num: 1,
            data: content.to_vec(),
        };
        client_sock.send(&data_pkt.encode()).await.unwrap();

        // receive ACK 1
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(pkt, Packet::Ack { block_num: 1 });

        // handler should complete
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        // verify file was written
        let written = std::fs::read(dir.path().join("uploaded.txt")).unwrap();
        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn wrq_successful_multi_block_upload() {
        let (dir, server_sock, client_sock) = setup_wrq().await;
        // exactly 512 bytes -> needs a second empty block
        let content = vec![0xCD; 512];

        let root = dir.path().to_path_buf();
        let content_clone = content.clone();
        let handle =
            tokio::spawn(async move { handle_wrq(&root, &server_sock, "multi.bin", None).await });

        let mut buf = [0u8; 600];

        // receive ACK 0
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Packet::decode(&buf[..len]).unwrap(),
            Packet::Ack { block_num: 0 }
        );

        // send DATA block 1 (full 512 bytes)
        let data1 = Packet::Data {
            block_num: 1,
            data: content_clone.clone(),
        };
        client_sock.send(&data1.encode()).await.unwrap();

        // receive ACK 1
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Packet::decode(&buf[..len]).unwrap(),
            Packet::Ack { block_num: 1 }
        );

        // send DATA block 2 (empty = end of transfer)
        let data2 = Packet::Data {
            block_num: 2,
            data: vec![],
        };
        client_sock.send(&data2.encode()).await.unwrap();

        // receive ACK 2
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Packet::decode(&buf[..len]).unwrap(),
            Packet::Ack { block_num: 2 }
        );

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        let written = std::fs::read(dir.path().join("multi.bin")).unwrap();
        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn wrq_path_traversal_rejected() {
        let (dir, server_sock, _client_sock) = setup_wrq().await;
        let root = dir.path().to_path_buf();

        let result = handle_wrq(&root, &server_sock, "../evil.txt", None).await;
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[tokio::test]
    async fn wrq_absolute_path_rejected() {
        let (dir, server_sock, _client_sock) = setup_wrq().await;
        let root = dir.path().to_path_buf();

        let result = handle_wrq(&root, &server_sock, "/tmp/evil.txt", None).await;
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[tokio::test]
    async fn wrq_file_already_exists() {
        let (dir, server_sock, _client_sock) = setup_wrq().await;
        // create the file first
        std::fs::write(dir.path().join("exists.txt"), b"already here").unwrap();

        let root = dir.path().to_path_buf();
        let result = handle_wrq(&root, &server_sock, "exists.txt", None).await;
        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_FILE_EXISTS);
        assert!(message.contains("already exists"));
    }

    #[test]
    fn resolve_write_path_normal() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path_for_write(dir.path(), "newfile.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_write_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path_for_write(dir.path(), "../escape.txt");
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[test]
    fn resolve_write_path_nonexistent_parent() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_path_for_write(dir.path(), "no_such_dir/file.txt");
        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_NOT_DEFINED);
        assert!(message.contains("parent directory"));
    }

    #[test]
    fn resolve_write_path_bad_root() {
        let result = resolve_path_for_write(Path::new("/nonexistent/root"), "file.txt");
        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_NOT_DEFINED);
        assert!(message.contains("server error"));
    }

    #[test]
    fn resolve_path_bad_root() {
        let result = resolve_path(Path::new("/nonexistent/root"), "file.txt");
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_FILE_NOT_FOUND);
    }

    #[test]
    fn resolve_write_path_allows_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("taken.txt"), b"data").unwrap();
        let result = resolve_path_for_write(dir.path(), "taken.txt");
        // file existence is now checked atomically during create_new(true),
        // so resolve_path_for_write no longer rejects existing files
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrq_timeout_no_data() {
        let (dir, server_sock, _client_sock) = setup_wrq().await;

        // drop client so no DATA arrives
        drop(_client_sock);

        let root = dir.path().to_path_buf();
        let result = tokio::time::timeout(
            Duration::from_secs(MAX_RETRIES as u64 * RETRY_TIMEOUT.as_secs() + 5),
            handle_wrq(&root, &server_sock, "timeout.txt", None),
        )
        .await
        .unwrap();

        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_NOT_DEFINED);
        assert!(message.contains("timed out"));

        // partial file is intentionally NOT cleaned up by pathname to prevent
        // symlink-swap attacks (see comment in handle_wrq verify_fd_within_root path)
        assert!(dir.path().join("timeout.txt").exists());
    }

    // --- blksize negotiation unit tests ---

    #[test]
    fn negotiate_blksize_above_server_max() {
        let options = packet::Options {
            blksize: Some(8192),
        };
        let result = negotiate_blksize(&options, 4096);
        assert_eq!(result, Some(4096));
    }

    #[test]
    fn negotiate_blksize_clamped_to_default_returns_none() {
        // when server_max=512, negotiation yields 512 which equals the default
        // block size — no point sending OACK for the standard size
        let options = packet::Options {
            blksize: Some(1024),
        };
        let result = negotiate_blksize(&options, DEFAULT_BLOCK_SIZE);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_blksize_exact_default_returns_none() {
        // client explicitly requests 512 — still no OACK needed
        let options = packet::Options { blksize: Some(512) };
        let result = negotiate_blksize(&options, 65464);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_blksize_below_minimum() {
        // sub-512 requests are declined (None) rather than clamped up,
        // because RFC 2348 requires server response <= client request
        let options = packet::Options { blksize: Some(256) };
        let result = negotiate_blksize(&options, 65464);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_blksize_no_option() {
        let options = packet::Options::default();
        let result = negotiate_blksize(&options, 65464);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_blksize_within_range() {
        let options = packet::Options {
            blksize: Some(1024),
        };
        let result = negotiate_blksize(&options, 8192);
        assert_eq!(result, Some(1024));
    }

    #[test]
    fn negotiate_blksize_at_exact_server_max() {
        let options = packet::Options {
            blksize: Some(4096),
        };
        let result = negotiate_blksize(&options, 4096);
        assert_eq!(result, Some(4096));
    }

    #[test]
    fn negotiate_blksize_zero() {
        let options = packet::Options { blksize: Some(0) };
        let result = negotiate_blksize(&options, 65464);
        assert_eq!(result, None);
    }

    // --- blksize integration tests ---

    #[tokio::test]
    async fn rrq_with_blksize_sends_oack() {
        let content = b"hello, negotiated blksize!";
        let (dir, server_sock, client_sock) = setup("blksize_rrq.txt", content).await;
        let root = dir.path().to_path_buf();

        let handle = tokio::spawn(async move {
            handle_rrq(&root, &server_sock, "blksize_rrq.txt", Some(1024)).await
        });

        // receive OACK
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Oack { options } => {
                assert_eq!(
                    options,
                    &packet::Options {
                        blksize: Some(1024),
                    }
                );
            }
            other => panic!("expected OACK, got {other:?}"),
        }

        // send ACK(0) to confirm OACK
        let ack0 = Packet::Ack { block_num: 0 };
        client_sock.send(&ack0.encode()).await.unwrap();

        // receive DATA(1) - entire content fits in one block (< 1024 bytes)
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Data { block_num, data } => {
                assert_eq!(*block_num, 1);
                assert_eq!(data, content);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // send ACK(1)
        let ack1 = Packet::Ack { block_num: 1 };
        client_sock.send(&ack1.encode()).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrq_with_blksize_sends_oack() {
        let (dir, server_sock, client_sock) = setup_wrq().await;
        let content = b"hello upload with blksize!";
        let root = dir.path().to_path_buf();

        let handle = tokio::spawn(async move {
            handle_wrq(&root, &server_sock, "blk_upload.txt", Some(1024)).await
        });

        // receive OACK (instead of ACK 0)
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Oack { options } => {
                assert_eq!(
                    options,
                    &packet::Options {
                        blksize: Some(1024),
                    }
                );
            }
            other => panic!("expected OACK, got {other:?}"),
        }

        // per RFC 2347, client acknowledges OACK for WRQ by sending DATA(1)
        let data_pkt = Packet::Data {
            block_num: 1,
            data: content.to_vec(),
        };
        client_sock.send(&data_pkt.encode()).await.unwrap();

        // receive ACK(1)
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(pkt, Packet::Ack { block_num: 1 });

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        let written = std::fs::read(dir.path().join("blk_upload.txt")).unwrap();
        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn rrq_no_blksize_no_oack() {
        // backward compat: no blksize option means no OACK, standard 512 transfer
        let content = b"backward compat test";
        let (dir, server_sock, client_sock) = setup("noopt.txt", content).await;
        let root = dir.path().to_path_buf();

        let handle =
            tokio::spawn(async move { handle_rrq(&root, &server_sock, "noopt.txt", None).await });

        // should receive DATA(1) directly (no OACK)
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Data { block_num, data } => {
                assert_eq!(*block_num, 1);
                assert_eq!(data, content);
            }
            other => panic!("expected Data (no OACK), got {other:?}"),
        }

        let ack1 = Packet::Ack { block_num: 1 };
        client_sock.send(&ack1.encode()).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rrq_with_blksize_multi_block() {
        let block_size = 1024;
        // 1124 bytes = 1 full block (1024) + 100 bytes (last block < blksize)
        let content = vec![0xAB; block_size + 100];
        let (dir, server_sock, client_sock) = setup("blkmulti.bin", &content).await;
        let root = dir.path().to_path_buf();

        let handle = tokio::spawn(async move {
            handle_rrq(&root, &server_sock, "blkmulti.bin", Some(block_size)).await
        });

        let mut buf = vec![0u8; 4 + block_size];

        // receive OACK
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert!(matches!(pkt, Packet::Oack { .. }));

        // send ACK(0)
        client_sock
            .send(&Packet::Ack { block_num: 0 }.encode())
            .await
            .unwrap();

        let mut received = Vec::new();

        // receive DATA(1) - full block
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        match Packet::decode(&buf[..len]).unwrap() {
            Packet::Data { block_num, data } => {
                assert_eq!(block_num, 1);
                assert_eq!(data.len(), block_size);
                received.extend_from_slice(&data);
            }
            other => panic!("expected Data block 1, got {other:?}"),
        }
        client_sock
            .send(&Packet::Ack { block_num: 1 }.encode())
            .await
            .unwrap();

        // receive DATA(2) - last block (< block_size)
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        match Packet::decode(&buf[..len]).unwrap() {
            Packet::Data { block_num, data } => {
                assert_eq!(block_num, 2);
                assert_eq!(data.len(), 100);
                received.extend_from_slice(&data);
            }
            other => panic!("expected Data block 2, got {other:?}"),
        }
        client_sock
            .send(&Packet::Ack { block_num: 2 }.encode())
            .await
            .unwrap();

        assert_eq!(received, content);

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrq_with_blksize_multi_block() {
        let (dir, server_sock, client_sock) = setup_wrq().await;
        let block_size = 1024;
        // 1124 bytes = 1 full block (1024) + 100 bytes (last block < blksize)
        let content: Vec<u8> = (0..block_size + 100).map(|i| (i % 256) as u8).collect();
        let root = dir.path().to_path_buf();

        let handle = tokio::spawn(async move {
            handle_wrq(
                &root,
                &server_sock,
                "blk_multi_upload.bin",
                Some(block_size),
            )
            .await
        });

        // receive OACK
        let mut buf = vec![0u8; 4 + block_size];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        match &pkt {
            Packet::Oack { options } => {
                assert_eq!(
                    options,
                    &packet::Options {
                        blksize: Some(1024),
                    }
                );
            }
            other => panic!("expected OACK, got {other:?}"),
        }

        // per RFC 2347, WRQ OACK is confirmed by sending DATA(1), not ACK(0)
        // send DATA(1) - full block (1024 bytes)
        let data1 = Packet::Data {
            block_num: 1,
            data: content[..block_size].to_vec(),
        };
        client_sock.send(&data1.encode()).await.unwrap();

        // receive ACK(1)
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Packet::decode(&buf[..len]).unwrap(),
            Packet::Ack { block_num: 1 }
        );

        // send DATA(2) - last block (100 bytes < 1024)
        let data2 = Packet::Data {
            block_num: 2,
            data: content[block_size..].to_vec(),
        };
        client_sock.send(&data2.encode()).await.unwrap();

        // receive ACK(2)
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Packet::decode(&buf[..len]).unwrap(),
            Packet::Ack { block_num: 2 }
        );

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        let written = std::fs::read(dir.path().join("blk_multi_upload.bin")).unwrap();
        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn rrq_oack_client_error() {
        let content = b"oack error test";
        let (dir, server_sock, client_sock) = setup("oack_err.txt", content).await;
        let root = dir.path().to_path_buf();

        let handle = tokio::spawn(async move {
            handle_rrq(&root, &server_sock, "oack_err.txt", Some(1024)).await
        });

        // receive OACK
        let mut buf = [0u8; 600];
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert!(matches!(pkt, Packet::Oack { .. }));

        // client rejects OACK by sending ERROR
        let err_pkt = Packet::Error {
            code: packet::ERR_ILLEGAL_OPERATION,
            message: "option not supported".into(),
        };
        client_sock.send(&err_pkt.encode()).await.unwrap();

        // handler should complete without error (graceful abort)
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }
}
