//! Tiny CLI that runs scrollback bytes through `RedactionFilter::standard`
//! and prints the result. Handy for spot-checking new patterns before
//! committing them, or for showing a fixture's redaction in a review.
//!
//! Usage:
//! ```text
//! echo 'enable secret 5 $1$abc$hash' | cargo run -p transit_agent --example redact-cli
//! cargo run -p transit_agent --example redact-cli -- path/to/scrollback.txt
//! ```

use std::io::Read;

use transit_agent::RedactionFilter;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let input = if args.is_empty() {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .expect("read stdin");
        buf
    } else {
        std::fs::read_to_string(&args[0]).unwrap_or_else(|e| panic!("read {}: {e}", args[0]))
    };

    print!("{}", RedactionFilter::standard().redact(&input));
}
