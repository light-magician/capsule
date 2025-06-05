# capsule-runtime

capsule-runtime is a minimal Rust sandbox that executes any CLI command
under `ptrace`, intercepts every system call in real time, and appends a timestamped
trace line to a unified log file. When a user runs `capsule trace <cmd>` the program forks
and the child enables `ptrace::traceme()` and executes the target. The parent becomes the
tracer, resuming the child for each syscall stop and recoridng syscall metadata.
A dedicated background thread owns the log file. For the time being, a non-blocking
logger implementation is used, but that is likely not practical for a production build
due to the necessity of the malicious syscall trapping.

This version of Capsule provides deterministic syscall visibility which will be
leveraged for building seccomp profiles.

Right now capsule-runtime runs only in linux containers.

### Running the linux container

```bash
# build container
docker compose up --build -d
# exec into container to run capsule-runtime with scripts
docker exec -it capsule-dev bash
```

### Building & Installation CLI

Once you have built the container and exec'd into it
you should be in the `/usr/src/app/` directory.
You can build the the project and install the CLI from there.
The demo scripts are located in `usr/src/app/scripts/` and
the logs will be generated inside `/tmp/`.

**Local build**:

```bash
# Binary at target/release/capsule
cargo build --release
```

**Global install** (runs from anywhere):

```bash
# Installs `capsule` into your cargo bin directory (usually ~/.cargo/bin)
cargo install --path . --force
# verify installation
capsule # should print help info
```

**Usage**:

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
# or tail the log live
capsule tail # then run trace same as above
```
