mod handler;
mod packet;
mod server;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "tftpr", version, about = "zero-config TFTP server")]
pub struct Cli {
    /// directory to serve (defaults to current directory)
    #[arg(default_value = ".")]
    pub directory: PathBuf,

    /// port to listen on
    #[arg(short, long, default_value_t = 69)]
    pub port: u16,

    /// maximum block size for blksize option negotiation (512-65464)
    #[arg(short = 'b', long = "blksize", default_value_t = 512)]
    pub blksize: usize,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let dir = cli.directory.canonicalize().unwrap_or_else(|_| {
        eprintln!(
            "error: directory '{}' does not exist or is not readable",
            cli.directory.display()
        );
        std::process::exit(1);
    });

    if !dir.is_dir() {
        eprintln!("error: '{}' is not a directory", dir.display());
        std::process::exit(1);
    }

    if cli.blksize < handler::DEFAULT_BLOCK_SIZE || cli.blksize > handler::MAX_BLOCK_SIZE {
        eprintln!("error: blksize must be between 512 and 65464");
        std::process::exit(1);
    }

    println!("serving {} on port {}", dir.display(), cli.port);

    let server = server::Server::bind(dir, cli.port, cli.blksize)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: failed to bind to port {}: {e}", cli.port);
            std::process::exit(1);
        });

    server.run().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults() {
        let cli = Cli::parse_from(["tftpr"]);
        assert_eq!(cli.directory, PathBuf::from("."));
        assert_eq!(cli.port, 69);
        assert_eq!(cli.blksize, 512);
    }

    #[test]
    fn cli_custom_directory_and_port() {
        let cli = Cli::parse_from(["tftpr", "/tmp", "-p", "1234"]);
        assert_eq!(cli.directory, PathBuf::from("/tmp"));
        assert_eq!(cli.port, 1234);
    }

    #[test]
    fn cli_long_port_flag() {
        let cli = Cli::parse_from(["tftpr", "--port", "8080"]);
        assert_eq!(cli.port, 8080);
    }

    #[test]
    fn cli_blksize_flag() {
        let cli = Cli::parse_from(["tftpr", "-b", "1024"]);
        assert_eq!(cli.blksize, 1024);
    }

    #[test]
    fn cli_long_blksize_flag() {
        let cli = Cli::parse_from(["tftpr", "--blksize", "8192"]);
        assert_eq!(cli.blksize, 8192);
    }
}
