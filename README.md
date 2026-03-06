# tftpr

A zero-config TFTP server (RFC 1350). Serves the current directory over TFTP with no required arguments.

## Features

- Read (RRQ) and write (WRQ) operations
- Octet transfer mode
- Path traversal protection
- Per-transfer ephemeral sockets (proper TFTP transfer IDs)
- Retransmission with configurable retries (3 attempts, 5s timeout)
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

## License

MIT
