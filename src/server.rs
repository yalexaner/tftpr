use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

use crate::handler;
use crate::log;
use crate::packet::{self, Packet};

const MAX_CONCURRENT_TRANSFERS: usize = 64;

pub struct Server {
    root: PathBuf,
    socket: UdpSocket,
    transfer_semaphore: Arc<Semaphore>,
}

impl Server {
    pub async fn bind(root: PathBuf, port: u16) -> std::io::Result<Self> {
        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        Self::bind_addr(root, addr).await
    }

    async fn bind_addr(root: PathBuf, addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Server {
            root,
            socket,
            transfer_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS)),
        })
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn run(&self) {
        let mut buf = [0u8; 1024];
        loop {
            let (len, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    log::error_raw(&format!("recv error: {e}"));
                    continue;
                }
            };

            let packet = match Packet::decode(&buf[..len]) {
                Ok(p) => p,
                Err(e) => {
                    log::error_raw(&format!("decode error from {peer}: {e}"));
                    let err_pkt = Packet::Error {
                        code: packet::ERR_ILLEGAL_OPERATION,
                        message: format!("malformed packet: {e}"),
                    };
                    let _ = self.socket.send_to(&err_pkt.encode(), peer).await;
                    continue;
                }
            };

            match &packet {
                Packet::Rrq { .. } | Packet::Wrq { .. } => {
                    let semaphore = self.transfer_semaphore.clone();
                    let permit = match semaphore.try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::error("server busy");
                            let err_pkt = Packet::Error {
                                code: packet::ERR_NOT_DEFINED,
                                message: "server busy".into(),
                            };
                            let _ = self.socket.send_to(&err_pkt.encode(), peer).await;
                            continue;
                        }
                    };
                    let root = self.root.clone();
                    let pkt = packet.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_request(root, peer, pkt).await {
                            log::error_raw(&format!("transfer error for {peer}: {e}"));
                        }
                    });
                }
                _ => {
                    let err_pkt = Packet::Error {
                        code: packet::ERR_ILLEGAL_OPERATION,
                        message: "expected RRQ or WRQ".into(),
                    };
                    let _ = self.socket.send_to(&err_pkt.encode(), peer).await;
                }
            }
        }
    }
}

async fn handle_request(root: PathBuf, peer: SocketAddr, packet: Packet) -> std::io::Result<()> {
    // bind ephemeral socket for this transfer
    let transfer_socket = UdpSocket::bind("0.0.0.0:0").await?;
    transfer_socket.connect(peer).await?;

    let (op, filename) = match &packet {
        Packet::Rrq { filename, .. } => ("GET", filename.clone()),
        Packet::Wrq { filename, .. } => ("PUT", filename.clone()),
        _ => return Ok(()),
    };

    log::request(op, &filename);

    let result = match packet {
        Packet::Rrq { filename, mode } => {
            if !mode.eq_ignore_ascii_case("octet") {
                Err(Packet::Error {
                    code: packet::ERR_ILLEGAL_OPERATION,
                    message: "only octet mode is supported".into(),
                })
            } else {
                handler::handle_rrq(&root, &transfer_socket, &filename).await
            }
        }
        Packet::Wrq { filename, mode } => {
            if !mode.eq_ignore_ascii_case("octet") {
                Err(Packet::Error {
                    code: packet::ERR_ILLEGAL_OPERATION,
                    message: "only octet mode is supported".into(),
                })
            } else {
                handler::handle_wrq(&root, &transfer_socket, &filename).await
            }
        }
        _ => return Ok(()),
    };

    match result {
        Ok(handler::TransferOutcome::Complete(bytes)) => log::success(&filename, bytes),
        Ok(handler::TransferOutcome::Aborted(bytes)) => {
            log::error(&format!(
                "{op} {filename} (aborted by client, {bytes} bytes transferred)"
            ));
        }
        Err(err_pkt) => {
            let msg = match &err_pkt {
                Packet::Error { message, .. } => message.as_str(),
                _ => "unknown error",
            };
            log::error(&format!("{op} {filename} ({msg})"));
            let _ = transfer_socket.send(&err_pkt.encode()).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn test_server() -> Server {
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        Server::bind_addr(PathBuf::from("."), addr).await.unwrap()
    }

    #[tokio::test]
    async fn server_binds_to_port() {
        let server = test_server().await;
        let addr = server.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn server_bind_public() {
        let server = Server::bind(PathBuf::from("."), 0).await.unwrap();
        let addr = server.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn rejects_ack_with_error() {
        let server = test_server().await;
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send an ACK packet (not RRQ/WRQ) to the server
        let ack = Packet::Ack { block_num: 1 };
        client.send_to(&ack.encode(), server_addr).await.unwrap();

        // should receive an ERROR response
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        let response = Packet::decode(&buf[..len]).unwrap();
        match response {
            Packet::Error { code, message } => {
                assert_eq!(code, packet::ERR_ILLEGAL_OPERATION);
                assert_eq!(message, "expected RRQ or WRQ");
            }
            other => panic!("expected Error packet, got {other:?}"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn rejects_unknown_opcode_with_error() {
        let server = test_server().await;
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send raw bytes with an invalid opcode (9)
        let bad_packet = [0x00, 0x09, 0x00];
        client.send_to(&bad_packet, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        let response = Packet::decode(&buf[..len]).unwrap();
        match response {
            Packet::Error { code, message } => {
                assert_eq!(code, packet::ERR_ILLEGAL_OPERATION);
                assert!(message.contains("malformed packet"));
            }
            other => panic!("expected Error packet, got {other:?}"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn accepts_wrq_and_dispatches() {
        let dir = tempfile::tempdir().unwrap();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind_addr(dir.path().to_path_buf(), addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send a WRQ
        let wrq = Packet::Wrq {
            filename: "upload.txt".into(),
            mode: "octet".into(),
        };
        client.send_to(&wrq.encode(), server_addr).await.unwrap();

        // should receive ACK 0 from an ephemeral port
        let mut buf = [0u8; 600];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        assert_ne!(from.port(), server_addr.port());

        let pkt = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(pkt, Packet::Ack { block_num: 0 });

        handle.abort();
    }

    #[tokio::test]
    async fn wrq_existing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("exists.txt"), b"data").unwrap();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind_addr(dir.path().to_path_buf(), addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let wrq = Packet::Wrq {
            filename: "exists.txt".into(),
            mode: "octet".into(),
        };
        client.send_to(&wrq.encode(), server_addr).await.unwrap();

        // should receive an ERROR from the ephemeral socket
        let mut buf = [0u8; 600];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        assert_ne!(from.port(), server_addr.port());

        let pkt = Packet::decode(&buf[..len]).unwrap();
        let Packet::Error { code, .. } = pkt else {
            panic!("expected Error packet, got {pkt:?}");
        };
        assert_eq!(code, packet::ERR_FILE_EXISTS);

        handle.abort();
    }

    #[tokio::test]
    async fn rejects_non_octet_mode_rrq() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.txt"), b"hello").unwrap();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind_addr(dir.path().to_path_buf(), addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send an RRQ with netascii mode (not octet)
        let rrq = Packet::Rrq {
            filename: "test.txt".into(),
            mode: "netascii".into(),
        };
        client.send_to(&rrq.encode(), server_addr).await.unwrap();

        // should receive an ERROR from the ephemeral socket
        let mut buf = [0u8; 600];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        assert_ne!(from.port(), server_addr.port());

        let pkt = Packet::decode(&buf[..len]).unwrap();
        let Packet::Error { code, message } = pkt else {
            panic!("expected Error packet, got {pkt:?}");
        };
        assert_eq!(code, packet::ERR_ILLEGAL_OPERATION);
        assert!(message.contains("only octet mode"));

        handle.abort();
    }

    #[tokio::test]
    async fn rejects_non_octet_mode_wrq() {
        let dir = tempfile::tempdir().unwrap();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind_addr(dir.path().to_path_buf(), addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send a WRQ with netascii mode (not octet)
        let wrq = Packet::Wrq {
            filename: "upload.txt".into(),
            mode: "netascii".into(),
        };
        client.send_to(&wrq.encode(), server_addr).await.unwrap();

        // should receive an ERROR from the ephemeral socket
        let mut buf = [0u8; 600];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        assert_ne!(from.port(), server_addr.port());

        let pkt = Packet::decode(&buf[..len]).unwrap();
        let Packet::Error { code, message } = pkt else {
            panic!("expected Error packet, got {pkt:?}");
        };
        assert_eq!(code, packet::ERR_ILLEGAL_OPERATION);
        assert!(message.contains("only octet mode"));

        handle.abort();
    }

    #[tokio::test]
    async fn accepts_rrq_and_dispatches() {
        // create a temp dir with a test file so the handler can serve it
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.txt"), b"hello").unwrap();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind_addr(dir.path().to_path_buf(), addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server = Arc::new(server);
        let s = server.clone();
        let handle = tokio::spawn(async move {
            s.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // send an RRQ
        let rrq = Packet::Rrq {
            filename: "test.txt".into(),
            mode: "octet".into(),
        };
        client.send_to(&rrq.encode(), server_addr).await.unwrap();

        // should receive a DATA response from an ephemeral port (not the main server port)
        let mut buf = [0u8; 600];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        // response comes from ephemeral socket, not main server socket
        assert_ne!(from.port(), server_addr.port());

        let pkt = Packet::decode(&buf[..len]).unwrap();
        match pkt {
            Packet::Data { block_num, data } => {
                assert_eq!(block_num, 1);
                assert_eq!(data, b"hello");
            }
            other => panic!("expected Data packet, got {other:?}"),
        }

        handle.abort();
    }
}
