// Simple build script - no special bindings needed for this hello world example
fn main() {
    println!("cargo:rerun-if-changed=src/");
}