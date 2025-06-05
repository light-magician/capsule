use std::path::PathBuf;

mod cli;
mod constants;
mod log;
mod sandbox;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("❌ {e:?}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    match cli::parse() {
        cli::Command::Trace { target, args, log } => {
            let mut argv = Vec::with_capacity(1 + args.len());
            argv.push(target);
            argv.extend(args);
            sandbox::trace(argv, log.map(PathBuf::from))?;
        }
    }
    Ok(())
}
