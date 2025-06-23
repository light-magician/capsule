Capsule today launches a traced process under strace, turns each raw line into a SyscallEvent, and dumps those events to a JSON-lines file. Everything else—context enrichment, action roll-ups, profile generation—is still on the whiteboard. The upgrade path is therefore to bolt richer stages onto the existing stream one at a time, keeping each stage independent so we can later swap strace out for eBPF without touching downstream logic.

Recommended implementation order
Action vocabulary + enum expansion

Sliding-window aggregator

Context enricher

Action/event log writer refactor

Profile generator

Structured-concurrency wiring

Step-by-step details

1. Action vocabulary
   Add explicit variants for file reads, writes, directory listings, socket connects, process spawns, signals, and a catch-all. This gives later stages a target schema.

2. Aggregator
   Maintain a map keyed by pid + fd (or socket). Merge consecutive compatible events until the window goes quiet, then emit one Action. Flush and remove the key when the fd closes or the process exits.

3. Enricher
   For every incoming SyscallEvent that lacks context, query /proc once, cache the result for a short TTL, and attach: full path for fds, user/group/cap set, socket endpoints, cwd, etc. Rate-limit expensive look-ups.

4. Action/event log writer
   Split the writer into two independent Tokio tasks: one receives raw events, the other receives actions. Both append in JSONL format, hash-chain each line, and publish to a broadcast channel for live subscribers.

5. Profile generator
   After the traced process exits, collect the set of unique Actions, summarise them into a simple YAML allow-list (paths, hosts, binaries), and write capsule-profile.yml. Later runs can diff live actions against this file to spot violations.

6. Structured-concurrency wiring
   Launch every stage (tracer, parser, enricher, aggregator, both writers, profile generator) inside a single JoinSet. Pass a cancellation token so that when the tracer finishes or fails, all other tasks shut down in order, flushing their buffers first.

Why this order works
Vocabulary first sets the contract. Aggregation next collapses noise early so later stages handle less data. Enrichment then attaches the extra insight needed for useful profiles. Separating writers prevents back-pressure in one stream from blocking the other. Finally, structured concurrency guarantees clean shutdowns and makes it easy to drop in an eBPF tracer later without rewriting aggregation, enrichment, or logging.

Further Details on Enrichment

The programme today traces a target with strace and writes raw syscall events. We are upgrading it to enrich each event with process-context metadata, roll multiple enriched events into higher-level actions, write both streams in tamper-evident JSONL, and finally emit an allow-list profile. We will do this in six incremental steps so that every stage stays independent and can survive a later switch from strace to eBPF.

Action vocabulary
Sliding-window aggregator
Context enricher
Separate writers for events and actions
Profile generator
Structured-concurrency wiring

Enrichment
The enricher sits between the parser and the aggregator. For every `SyscallEvent` it gathers extra facts—PID, parent PID, µs timestamp, executable path, current working directory, original argv, uid/gid/cap set, fd→path, socket endpoints, return code and byte count, namespace or cgroup IDs, mmap regions, signals, exit status and resource usage. Each fact adds clarity: who spawned the call, where data went, what privileges were active, whether the call succeeded, and how the process mutated its environment. The enricher resolves anything strace already prints (`-yy` gives fd paths) and fills the gaps by reading `/proc/<pid>/...`. Look-ups are memoised with a short TTL to avoid hammering the filesystem. Expensive calls (readlink, getsockname) are throttled with a bounded semaphore so enrichment never blocks the parse loop.

Modularity for a future eBPF tracer
Nothing downstream of the enricher depends on how the raw event arrived. The tracer task is the only piece that will be swapped. Keep the event schema stable, expose a single async channel, and guard tracer-specific fields behind optional structs so eBPF can later push richer data without breaking the pipe.

Multithreading model
One Tokio task runs strace and pushes stderr into a bounded channel. The parser task reads that channel and produces `SyscallEvent`s. The enricher task consumes events, does its cached `/proc` look-ups under a small semaphore, and publishes enriched events. The aggregator task merges them into actions on its own channel. Two writer tasks independently dump events and actions to disk and broadcast them for live tailers. A profile task waits for the tracer to finish, then scans the completed action log and writes the YAML allow-list. All tasks live in a `JoinSet` protected by a cancellation token so that failure or completion of the tracer cleanly tears everything down in order.

This structure keeps I/O, enrichment, aggregation, and persistence isolated, scales across cores, and positions us to drop in an eBPF-based tracer later with minimal refactor.
