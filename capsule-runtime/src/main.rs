use std::path::PathBuf;

mod cli;
mod constants;
mod log; // TODO: tail and log should be in a log/ crate
mod run;
mod tail;
mod trace;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("❌ {e:?}");
        std::process::exit(1);
    }
}

// real_main is defined to utilize anyhow::Result
// which allows for free use of ?
//
fn real_main() -> anyhow::Result<()> {
    match cli::parse() {
        cli::Command::Trace { target, args, log } => {
            let mut argv = Vec::with_capacity(1 + args.len());
            argv.push(target);
            argv.extend(args);
            trace::trace(argv, log.map(PathBuf::from))?;
        }
        cli::Command::Tail { file } => {
            tail::tail(file.clone())?;
        }
    }
    Ok(())
}
