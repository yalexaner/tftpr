# Zero-Config TFTP Server CLI Tool

## Overview

Implement a minimal TFTP server (RFC 1350) as a CLI tool. Supports RRQ and WRQ operations. Zero-config means it works out of the box: serve the current directory on port 69 with no required arguments.

## Context

- Files involved: `Cargo.toml`, `src/main.rs`, new modules under `src/`
- Related patterns: fresh Rust 2024 edition project, no existing code
- Dependencies: `clap` (CLI parsing), `tokio` (async UDP), `thiserror` (error types)

## Development Approach

- **Testing approach**: TDD where practical (packet parsing), code-first for networking
- Complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: Project setup and CLI

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`

- [x] add dependencies: `clap` (with derive), `tokio` (with net, rt-multi-thread, macros, io-util, fs features), `thiserror`
- [x] define CLI with clap: optional positional `directory` (defaults to `.`), optional `--port` / `-p` (defaults to 69)
- [x] validate that directory exists and is readable at startup
- [x] print startup message with serving directory and port
- [x] write tests: CLI parsing defaults, custom directory/port, nonexistent directory error

### Task 2: TFTP packet types and parsing

**Files:**
- Create: `src/packet.rs`
- Modify: `src/main.rs` (add module)

- [x] define `Packet` enum: `Rrq { filename, mode }`, `Wrq { filename, mode }`, `Data { block_num, data }`, `Ack { block_num }`, `Error { code, message }`
- [x] implement `Packet::decode(buf: &[u8]) -> Result<Packet>` - parse raw UDP bytes into packet
- [x] implement `Packet::encode(&self) -> Vec<u8>` - serialize packet to bytes
- [x] define TFTP error codes as constants (file not found, access violation, disk full, etc.)
- [x] write tests: round-trip encode/decode for each packet type, malformed packet errors, edge cases (empty filename, max block data)

### Task 3: Server core and request dispatch

**Files:**
- Create: `src/server.rs`
- Modify: `src/main.rs`

- [x] create `Server` struct holding the root directory path and bound `UdpSocket` on the configured port
- [x] implement main loop: receive packet on listening socket, decode it, reject non-RRQ/WRQ packets with error response
- [x] for each valid request, spawn a tokio task that binds a new ephemeral UDP socket (transfer ID) and handles the transfer
- [x] write tests: server binds to port, rejects unknown opcodes with ERROR packet

### Task 4: RRQ handler - file downloads

**Files:**
- Create: `src/handler.rs`
- Modify: `src/server.rs`

- [x] on RRQ: resolve filename relative to root directory, reject path traversal attempts (e.g. `../`)
- [x] open the file, read in 512-byte blocks, send DATA packets, wait for ACK before sending next block
- [x] handle retransmission on timeout (3 retries, 5s timeout per attempt)
- [x] send appropriate ERROR packet if file not found or permission denied
- [x] last DATA packet has < 512 bytes of data, signaling transfer complete
- [x] write tests: successful file transfer, file not found error, path traversal rejected, timeout/retry behavior

### Task 5: WRQ handler - file uploads

**Files:**
- Modify: `src/handler.rs`

- [x] on WRQ: resolve filename relative to root directory, reject path traversal attempts
- [x] send initial ACK (block 0) to accept the transfer
- [x] receive DATA packets, write to file, send ACK for each block
- [x] handle retransmission on timeout (same policy as RRQ)
- [x] detect transfer complete when DATA packet < 512 bytes
- [x] send ERROR if file already exists or disk write fails
- [x] write tests: successful upload, path traversal rejected, duplicate file error, write failure handling

### Task 6: Verify acceptance criteria

- [x] manual test: start server, use a tftp client to download and upload a file
- [x] run full test suite: `cargo test`
- [x] run linter: `cargo clippy`
- [x] verify test coverage meets 80%+

### Task 7: Update documentation

- [x] update README.md with usage instructions, examples, and feature overview
- [x] move this plan to `docs/plans/completed/`
