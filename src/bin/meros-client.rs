//! `meros-client <command>`: reads the command's JSON input from stdin (or
//! `--input <file>`), prints one JSON object on stdout and exits with a code
//! from `meros_client::cli::exit`. `meros-client commands` lists the
//! commands; `docs/cli.md` documents them.

use std::io::Read;
use std::sync::Arc;

use meros_client::ReqwestTransport;
use meros_client::cli::{self, COMMANDS, exit};
use serde_json::{Value, json};

const USAGE: &str = "usage: meros-client <command> [--input <file>]
       meros-client commands
       meros-client --version

Reads the command's input as one JSON object from stdin (or the file) and
prints one JSON object. See docs/cli.md.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, output) = match args.first().map(String::as_str) {
        None | Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            std::process::exit(if args.is_empty() {
                exit::USAGE
            } else {
                exit::OK
            });
        }
        Some("--version" | "-V") => (
            exit::OK,
            json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}),
        ),
        Some("commands") => (exit::OK, json!({"ok": true, "commands": COMMANDS})),
        Some(command) => match read_input(&args[1..]) {
            Ok(input) => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a Tokio runtime");
                let outcome =
                    runtime.block_on(cli::run(command, input, Arc::new(ReqwestTransport::new())));
                (outcome.exit, outcome.output)
            }
            Err(message) => (
                exit::USAGE,
                json!({"ok": false, "error": {"code": "bad_input", "message": message}}),
            ),
        },
    };
    println!("{output}");
    std::process::exit(code);
}

fn read_input(rest: &[String]) -> Result<Value, String> {
    let text = match rest {
        [] => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| format!("Can't read stdin: {e}"))?;
            s
        }
        [flag, path] if flag == "--input" => {
            std::fs::read_to_string(path).map_err(|e| format!("Can't read {path}: {e}"))?
        }
        _ => return Err(format!("Unexpected arguments: {}", rest.join(" "))),
    };
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).map_err(|e| format!("The input is not JSON: {e}"))
}
