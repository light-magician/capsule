exec into the container which now shares the file space with your project

```bash
docker exec -it capsule-dev bash
```

test with strace logging of syscalls

## Building & Installation CLI

1. **Local build**:
   ```bash
   cargo build --release
   # Binary at target/release/capsule
   ```
2. **Global install** (runs from anywhere):
   ```bash
   cargo install --path . --force
   # Installs `capsule` into your cargo bin directory (usually ~/.cargo/bin)
   ```
3. **Usage**:

test it out on a script

```bash
# move into scripts dir
cd scripts
# Run `capsule trace` to view options
capsule trace
# Run a script with capsule
capsule run python3 hello.py # should see `hello world` printed
# Verify an audit log
cd /tmp
cat capsule_syscalls.log
```
