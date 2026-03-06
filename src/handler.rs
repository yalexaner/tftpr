use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::packet::{self, Packet, MAX_DATA_LEN};

const MAX_RETRIES: u32 = 3;
const RETRY_TIMEOUT: Duration = Duration::from_secs(5);

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
    if full_path.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
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


/// handles a read request: sends the file to the peer in 512-byte DATA blocks.
pub async fn handle_rrq(
    root: &Path,
    socket: &UdpSocket,
    filename: &str,
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

    let mut block_num: u16 = 1;
    let mut buf = vec![0u8; MAX_DATA_LEN];

    loop {
        let mut bytes_read = 0;
        while bytes_read < MAX_DATA_LEN {
            let n = file.read(&mut buf[bytes_read..]).await.map_err(|_| Packet::Error {
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

        // last block: data < 512 bytes signals end of transfer
        if bytes_read < MAX_DATA_LEN {
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

/// handles a write request: receives the file from the peer in 512-byte DATA blocks.
pub async fn handle_wrq(
    root: &Path,
    socket: &UdpSocket,
    filename: &str,
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

    // send ACK 0 to accept the transfer
    let ack0 = Packet::Ack { block_num: 0 };
    socket.send(&ack0.encode()).await.map_err(|_| {
        // clean up file if we can't communicate with the client
        let path_clone = path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&path_clone).await;
        });
        Packet::Error {
            code: packet::ERR_NOT_DEFINED,
            message: "failed to send initial ACK".into(),
        }
    })?;

    let mut expected_block: u16 = 1;

    loop {
        // wait for DATA with retries
        let data = match wait_for_data(socket, expected_block).await {
            Ok(d) => d,
            Err(client_error) => {
                // clean up partial file
                let _ = tokio::fs::remove_file(&path).await;
                if client_error {
                    // client sent ERROR - don't respond per RFC 1350 Section 5
                    return Ok(());
                }
                return Err(Packet::Error {
                    code: packet::ERR_NOT_DEFINED,
                    message: "transfer timed out".into(),
                });
            }
        };

        // write data to file
        file.write_all(&data).await.map_err(|_| {
            // clean up partial file on write failure (best-effort, sync context)
            let path_clone = path.clone();
            tokio::spawn(async move {
                let _ = tokio::fs::remove_file(&path_clone).await;
            });
            Packet::Error {
                code: packet::ERR_DISK_FULL,
                message: "disk write failed".into(),
            }
        })?;

        // send ACK for this block
        let ack = Packet::Ack {
            block_num: expected_block,
        };
        let _ = socket.send(&ack.encode()).await;

        // last block: data < 512 bytes signals end of transfer
        if data.len() < MAX_DATA_LEN {
            break;
        }

        if expected_block == u16::MAX {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(Packet::Error {
                code: packet::ERR_NOT_DEFINED,
                message: "file too large for TFTP".into(),
            });
        }
        expected_block += 1;
    }

    file.flush().await.map_err(|_| {
        let path_clone = path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&path_clone).await;
        });
        Packet::Error {
            code: packet::ERR_DISK_FULL,
            message: "disk write failed".into(),
        }
    })?;

    Ok(())
}

/// waits for a DATA packet with the expected block number, with retries and timeout.
/// returns Ok(data) on success, Err(true) if client sent ERROR (fatal),
/// Err(false) on timeout after retries.
async fn wait_for_data(socket: &UdpSocket, expected_block: u16) -> Result<Vec<u8>, bool> {
    let mut timeouts = 0u32;
    loop {
        let mut recv_buf = [0u8; 4 + MAX_DATA_LEN];
        let result = tokio::time::timeout(RETRY_TIMEOUT, socket.recv(&mut recv_buf)).await;

        match result {
            Ok(Ok(len)) => match Packet::decode(&recv_buf[..len]) {
                Ok(Packet::Data { block_num, data }) if block_num == expected_block => {
                    return Ok(data);
                }
                Ok(Packet::Error { .. }) => return Err(true),
                _ => {
                    // wrong block or non-DATA packet - resend previous ACK
                    let prev_ack = Packet::Ack {
                        block_num: expected_block.wrapping_sub(1),
                    };
                    let _ = socket.send(&prev_ack.encode()).await;
                }
            },
            _ => {
                // timeout or recv error - resend previous ACK to trigger retransmit
                timeouts += 1;
                if timeouts >= MAX_RETRIES {
                    return Err(false);
                }
                let prev_ack = Packet::Ack {
                    block_num: expected_block.wrapping_sub(1),
                };
                let _ = socket.send(&prev_ack.encode()).await;
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
        let handle = tokio::spawn(async move {
            handle_rrq(&root, &server_sock, "small.txt").await
        });

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
        let handle = tokio::spawn(async move {
            handle_rrq(&root, &server_sock, "multi.bin").await
        });

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
        let result = handle_rrq(&root, &server_sock, "nope.txt").await;
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
        let result = handle_rrq(&root, &server_sock, "../etc/passwd").await;
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
            handle_rrq(&root, &server_sock, "timeout.txt"),
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
        let handle = tokio::spawn(async move {
            handle_wrq(&root, &server_sock, "uploaded.txt").await
        });

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
        let handle = tokio::spawn(async move {
            handle_wrq(&root, &server_sock, "multi.bin").await
        });

        let mut buf = [0u8; 600];

        // receive ACK 0
        let len = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Packet::decode(&buf[..len]).unwrap(), Packet::Ack { block_num: 0 });

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
        assert_eq!(Packet::decode(&buf[..len]).unwrap(), Packet::Ack { block_num: 1 });

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
        assert_eq!(Packet::decode(&buf[..len]).unwrap(), Packet::Ack { block_num: 2 });

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

        let result = handle_wrq(&root, &server_sock, "../evil.txt").await;
        let Err(Packet::Error { code, .. }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_ACCESS_VIOLATION);
    }

    #[tokio::test]
    async fn wrq_absolute_path_rejected() {
        let (dir, server_sock, _client_sock) = setup_wrq().await;
        let root = dir.path().to_path_buf();

        let result = handle_wrq(&root, &server_sock, "/tmp/evil.txt").await;
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
        let result = handle_wrq(&root, &server_sock, "exists.txt").await;
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
            handle_wrq(&root, &server_sock, "timeout.txt"),
        )
        .await
        .unwrap();

        let Err(Packet::Error { code, message }) = result else {
            panic!("expected Packet::Error, got {result:?}");
        };
        assert_eq!(code, packet::ERR_NOT_DEFINED);
        assert!(message.contains("timed out"));

        // partial file should be cleaned up
        assert!(!dir.path().join("timeout.txt").exists());
    }
}
