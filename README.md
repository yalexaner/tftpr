# tftpr

A zero-config TFTP server (RFC 1350). Serves the current directory over TFTP with no required arguments.

## Features

- Read (RRQ) and write (WRQ) operations
- Octet transfer mode
- Path traversal protection
- Per-transfer ephemeral sockets (proper TFTP transfer IDs)
- Retransmission with configurable retries (3 attempts, 5s timeout)
- Colored, timestamped server logs (auto-disabled when piped)
- Async I/O via tokio

## Installation

```
cargo install --path .
```

## Usage

```
tftpr [OPTIONS] [DIRECTORY]
```

### Arguments

- `DIRECTORY` - directory to serve (defaults to current directory)

### Options

- `-p, --port <PORT>` - port to listen on (default: 69)
- `-V, --version` - print version
- `-h, --help` - print help

### Examples

Serve the current directory on the default TFTP port (69):

```
sudo tftpr
```

Serve a specific directory on a custom port:

```
tftpr /srv/tftp -p 6969
```

Download a file using a TFTP client:

```
tftp localhost 6969 -c get myfile.txt
```

Upload a file:

```
tftp localhost 6969 -c put newfile.txt
```

## Releasing

Releases are automated with [cargo-dist](https://opensource.axo.dev/cargo-dist/) and [cargo-release](https://github.com/crate-ci/cargo-release).

To publish a new release:

```
cargo release patch   # or minor, major
```

This bumps the version in Cargo.toml, commits, tags, and pushes. The pushed tag triggers a GitHub Actions workflow that builds binaries for all supported platforms and creates a GitHub release.

Supported platforms:
- x86_64-unknown-linux-gnu
- aarch64-unknown-linux-gnu
- x86_64-apple-darwin
- aarch64-apple-darwin
- x86_64-pc-windows-msvc

## License

MIT
