use std::fs::OpenOptions;
use std::io::Write;

fn log_event(event: &CapsuleEvent) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("capsule.log")?;

    let json = serde_json::to_string(event)?;
    let hash = event.compute_hash().to_hex().to_string();
    writeln!(file, "{}|{}", json, hash)?;
    Ok(())
}
