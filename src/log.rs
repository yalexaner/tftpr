use std::io::IsTerminal;
use std::sync::LazyLock;

use chrono::Local;

const GRAY: &str = "\x1b[90m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

static USE_COLOR: LazyLock<bool> = LazyLock::new(|| std::io::stdout().is_terminal());

fn timestamp() -> String {
    Local::now().format("%d %b %H:%M:%S").to_string()
}

/// replaces control characters in user-supplied strings to prevent
/// ANSI escape injection via crafted TFTP filenames.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// formats a log line with optional body color.
/// `color` is an ANSI escape for the body portion; `None` means default color.
fn format_line(body: &str, color: Option<&str>, use_color: bool) -> String {
    let ts = timestamp();
    let body = sanitize(body);
    if use_color {
        let (c, r) = color.map(|c| (c, RESET)).unwrap_or(("", ""));
        format!("{GRAY}{ts}{RESET}  {c}{body}{r}")
    } else {
        format!("{ts}  {body}")
    }
}

/// prints `{ts}  {msg}` — for startup messages
pub fn info(msg: &str) {
    println!("{}", format_line(msg, None, *USE_COLOR));
}

/// prints `{ts}  -> {op} {filename}` — for incoming requests
pub fn request(op: &str, filename: &str) {
    println!(
        "{}",
        format_line(&format!("-> {op} {filename}"), None, *USE_COLOR)
    );
}

/// prints `{ts}  <- {filename} ({bytes} bytes)` in green — for successful transfers
pub fn success(filename: &str, bytes: u64) {
    println!(
        "{}",
        format_line(
            &format!("<- {filename} ({bytes} bytes)"),
            Some(GREEN),
            *USE_COLOR
        )
    );
}

/// prints `{ts}  xx {msg}` in red — for request-level errors
pub fn error(msg: &str) {
    println!(
        "{}",
        format_line(&format!("xx {msg}"), Some(RED), *USE_COLOR)
    );
}

/// prints `{ts}  {msg}` in red — for internal errors (recv/decode), no xx prefix
pub fn error_raw(msg: &str) {
    println!("{}", format_line(msg, Some(RED), *USE_COLOR));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format_matches_spec() {
        let ts = timestamp();
        // expected format: "DD Mon HH:MM:SS" e.g. "12 Mar 14:05:32"
        let parts: Vec<&str> = ts.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3, "expected 3 space-separated parts in '{ts}'");

        // DD: two digits
        assert_eq!(parts[0].len(), 2, "day should be 2 chars: '{}'", parts[0]);
        assert!(
            parts[0].chars().all(|c| c.is_ascii_digit()),
            "day should be digits: '{}'",
            parts[0]
        );

        // Mon: three letters
        assert_eq!(parts[1].len(), 3, "month should be 3 chars: '{}'", parts[1]);
        assert!(
            parts[1].chars().all(|c| c.is_ascii_alphabetic()),
            "month should be letters: '{}'",
            parts[1]
        );

        // HH:MM:SS
        let time_parts: Vec<&str> = parts[2].split(':').collect();
        assert_eq!(
            time_parts.len(),
            3,
            "time should have 3 colon-separated parts: '{}'",
            parts[2]
        );
        for part in &time_parts {
            assert_eq!(part.len(), 2, "time component should be 2 chars: '{part}'");
            assert!(
                part.chars().all(|c| c.is_ascii_digit()),
                "time component should be digits: '{part}'"
            );
        }
    }

    #[test]
    fn use_color_matches_stdout_is_terminal() {
        // USE_COLOR should reflect whether stdout is actually a terminal.
        // this test verifies the LazyLock initializes consistently with
        // a direct is_terminal() check, regardless of environment.
        assert_eq!(*USE_COLOR, std::io::stdout().is_terminal());
    }

    #[test]
    fn colored_output_contains_ansi_codes() {
        let info = format_line("serving /data on port 69", None, true);
        assert!(
            info.contains("\x1b[90m"),
            "info should contain gray ANSI code"
        );
        assert!(info.contains("\x1b[0m"), "info should contain reset code");

        let req = format_line("-> GET test.txt", None, true);
        assert!(
            req.contains("\x1b[90m"),
            "request should contain gray ANSI code"
        );
        assert!(
            req.contains("-> GET test.txt"),
            "request should contain arrow and filename"
        );

        let succ = format_line("<- test.txt (4096 bytes)", Some(GREEN), true);
        assert!(
            succ.contains("\x1b[32m"),
            "success should contain green ANSI code"
        );
        assert!(
            succ.contains("<- test.txt (4096 bytes)"),
            "success should contain filename and bytes"
        );

        let err = format_line("xx access violation", Some(RED), true);
        assert!(
            err.contains("\x1b[31m"),
            "error should contain red ANSI code"
        );
        assert!(
            err.contains("xx access violation"),
            "error should contain xx prefix and message"
        );

        let err_raw = format_line("recv error: connection reset", Some(RED), true);
        assert!(
            err_raw.contains("\x1b[31m"),
            "error_raw should contain red ANSI code"
        );
        assert!(
            !err_raw.contains("xx"),
            "error_raw should not contain xx prefix"
        );
    }

    #[test]
    fn no_color_output_has_no_ansi_codes() {
        let info = format_line("serving /data on port 69", None, false);
        assert!(
            !info.contains("\x1b["),
            "no-color info should not contain ANSI codes"
        );

        let req = format_line("-> GET test.txt", None, false);
        assert!(
            !req.contains("\x1b["),
            "no-color request should not contain ANSI codes"
        );

        let succ = format_line("<- test.txt (4096 bytes)", Some(GREEN), false);
        assert!(
            !succ.contains("\x1b["),
            "no-color success should not contain ANSI codes"
        );

        let err = format_line("xx access violation", Some(RED), false);
        assert!(
            !err.contains("\x1b["),
            "no-color error should not contain ANSI codes"
        );

        let err_raw = format_line("recv error: connection reset", Some(RED), false);
        assert!(
            !err_raw.contains("\x1b["),
            "no-color error_raw should not contain ANSI codes"
        );
    }

    #[test]
    fn sanitize_strips_control_characters() {
        // ANSI escape sequence in a crafted filename
        let malicious = "evil\x1b[2Jfile.txt";
        let clean = sanitize(malicious);
        assert!(!clean.contains('\x1b'), "ESC byte should be replaced");
        assert!(
            clean.contains("file.txt"),
            "normal text should be preserved"
        );

        // verify it appears sanitized in formatted output
        let line = format_line(&format!("-> GET {malicious}"), None, true);
        assert!(
            !line.contains("\x1b[2J"),
            "injected ANSI sequence should not appear in output"
        );
    }
}
