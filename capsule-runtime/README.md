### running

1. Build (debug)

```bash
cargo build
```

2. Build (release)

```bash
cargo build --release
```

3. Run your CLI (debug build)

```bash
cargo run --bin capsule-runtime -- echo hello
```

4. (Or invoke the built binary directly)

```bash
./target/debug/capsule-runtime echo hello
```

5. Run the release‐optimized binary

```bash
./target/release/capsule-runtime echo hello
```
