// remove: mod cli;
use anyhow::Result;
use capsule_runtime::cli; // <–– the library crate name

fn main() {
    // cli::run() already does parse → dispatch → exit-code
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
