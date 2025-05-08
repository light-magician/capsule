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

### container

We use Docker to ensure seccomp support and a consistent Rust toolchain.

```bash
docker-compose up --build -d
```

verify

```bash
docker ps
```

```
CONTAINER ID   IMAGE                        COMMAND   CREATED              STATUS              PORTS     NAMES
f0ba356a1761   capsule-runtime-dev:latest   "bash"    About a minute ago   Up About a minute             capsule-dev
```

exec into the container which now shares the file space with your project

```bash
docker exec -it capsule-dev bash
```

```bash
cargo build
cargo test -- --test-threads=1
cargo run -- echo hello
```

test with strace logging of syscalls

```bash
strace -ff -e trace=all /usr/src/app/target/debug/capsule-runtime echo hello
```

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

   ```bash
   # Run under sandbox
   capsule run --policy capsule.yaml -- mcp-fs-server --root /data

   # Verify an audit log
   capsule verify /var/log/capsule.log
   ```

### Syscall tracing

It is imperitive to know what syscalls happen underneath common
terminal commands, so they can be allowed by the sandbox.
It is also important to know the sequences so that diversion from those
sequences can be flagged and the processes can be killed, fenced off,
or sent back to the user in the form of an `in-the-loop` prompting.

using `strace` helps identify the basic sequence of syscalls that happen
under the hood of a given command.

```bash
strace -ff -e trace=all -o trace.out capsule-runtime echo hello
```
