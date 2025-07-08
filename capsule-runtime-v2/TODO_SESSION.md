# Capsule Runtime V2 - Implementation TODO Session

## Phase 1: Project Setup ✅
- [x] Create capsule-runtime-v2/ directory structure
- [x] Create workspace Cargo.toml

## Phase 2: Core Foundation

### 2.1 capsule-tracer Library (Linux strace support)
- [ ] Create `capsule-tracer/` directory and `Cargo.toml`
- [ ] Create `capsule-tracer/src/lib.rs` with main exports
- [ ] Create `capsule-tracer/src/platform.rs` - Platform detection trait
- [ ] Create `capsule-tracer/src/linux.rs` - Linux strace implementation
  - [ ] `LinuxTracer` struct with subprocess management
  - [ ] `start_trace()` method - spawn strace with correct flags
  - [ ] `read_trace_line()` method - async line reading from stderr
  - [ ] `stop_trace()` method - graceful subprocess termination
- [ ] Create `capsule-tracer/src/error.rs` - Tracer-specific errors
- [ ] Test basic strace subprocess spawning and line reading

### 2.2 capsule-core Library (Data Models)
- [ ] Create `capsule-core/` directory and `Cargo.toml`
- [ ] Create `capsule-core/src/lib.rs` with main exports
- [ ] Create `capsule-core/src/event.rs` - ProcessEvent and ProcessEventType
- [ ] Create `capsule-core/src/tree.rs` - ProcessNode and ProcessTree
- [ ] Create `capsule-core/src/workflow.rs` - AgentWorkflow and ProcessLabel enums
- [ ] Create `capsule-core/src/synthesis.rs` - AISynthesis and reporting structures
- [ ] Create `capsule-core/src/error.rs` - Common error types
- [ ] Test serialization/deserialization of data models

### 2.3 capsule-parser Library (strace -> ProcessEvent)
- [ ] Create `capsule-parser/` directory and `Cargo.toml`
- [ ] Create `capsule-parser/src/lib.rs` with main exports
- [ ] Create `capsule-parser/src/parser.rs` - Parser trait and implementations
- [ ] Create `capsule-parser/src/strace.rs` - StraceParser implementation
  - [ ] Regex patterns for process syscalls (execve, clone, fork, exit_group)
  - [ ] Extract PID, PPID, command line, exit codes
  - [ ] Convert to ProcessEvent structs
- [ ] Create `capsule-parser/src/error.rs` - Parser-specific errors
- [ ] Test parsing real strace output samples

### 2.4 capsule-tracker Library (Process Tree + File Streaming)
- [ ] Create `capsule-tracker/` directory and `Cargo.toml`
- [ ] Create `capsule-tracker/src/lib.rs` with main exports
- [ ] Create `capsule-tracker/src/tracker.rs` - ProcessTracker main struct
- [ ] Create `capsule-tracker/src/tree.rs` - ProcessTree management
  - [ ] Add/remove processes from tree
  - [ ] Parent-child relationship tracking
  - [ ] Active PID management
- [ ] Create `capsule-tracker/src/file_writer.rs` - Async file streaming
  - [ ] Append ProcessEvents to JSONL file
  - [ ] Periodic state persistence
  - [ ] Graceful shutdown handling
- [ ] Create `capsule-tracker/src/error.rs` - Tracker-specific errors
- [ ] Test concurrent tree updates and file operations

## Phase 3: Classification and Reporting

### 3.1 capsule-classifier Library (Agent/Tool Classification)
- [ ] Create `capsule-classifier/` directory and `Cargo.toml`
- [ ] Create `capsule-classifier/src/lib.rs` with main exports
- [ ] Create `capsule-classifier/src/classifier.rs` - Classification engine
- [ ] Create `capsule-classifier/src/rules.rs` - Agent vs Tool detection rules
- [ ] Create `capsule-classifier/src/workflow.rs` - AgentWorkflow detection
  - [ ] FileAnalysis patterns
  - [ ] NetworkCommunication patterns
  - [ ] CodeGeneration patterns
  - [ ] RepositoryOperation patterns
  - [ ] SystemExploration patterns
  - [ ] SecurityOperation patterns
- [ ] Test classification accuracy on sample data

### 3.2 capsule-reporter Library (Output Generation)
- [ ] Create `capsule-reporter/` directory and `Cargo.toml`
- [ ] Create `capsule-reporter/src/lib.rs` with main exports
- [ ] Create `capsule-reporter/src/reporter.rs` - Reporter main struct
- [ ] Create `capsule-reporter/src/human.rs` - Human-readable tree output
- [ ] Create `capsule-reporter/src/ai_synthesis.rs` - AI-optimized format
- [ ] Create `capsule-reporter/src/templates.rs` - Output templates
- [ ] Test all output formats with sample data

## Phase 4: CLI Integration

### 4.1 CLI Binary (Main Orchestration)
- [ ] Create `cli/` directory and `Cargo.toml`
- [ ] Create `cli/src/main.rs` - Entry point and argument parsing
- [ ] Create `cli/src/pipeline.rs` - Tokio async pipeline orchestration
- [ ] Create `cli/src/commands.rs` - Command implementations
  - [ ] `run` command - trace a process
  - [ ] `report` command - generate reports
  - [ ] `export` command - AI-ready export
- [ ] Create `cli/src/config.rs` - Configuration management
- [ ] Test end-to-end pipeline with real processes

## Phase 5: Testing and Polish

### 5.1 Unit Tests
- [ ] Add tests for each library in `tests/` directories
- [ ] Test error conditions and edge cases
- [ ] Test async cancellation and cleanup

### 5.2 Integration Tests
- [ ] Create `cli/tests/integration_tests.rs`
- [ ] Test full pipeline with sample processes
- [ ] Test platform detection and switching
- [ ] Test concurrent processing and file I/O

### 5.3 Documentation and Examples
- [ ] Add rustdoc comments to all public APIs
- [ ] Create usage examples in README
- [ ] Add performance benchmarks

## Implementation Order Strategy

**Start with strace first** because:
1. It's the data source - everything depends on getting trace data
2. Can test independently by running strace and reading output
3. Informs the data model design based on actual strace output
4. Allows early validation of platform support

**Then data models** because:
1. Parser needs ProcessEvent to convert strace lines
2. Tracker needs ProcessTree to manage state
3. Everything else depends on these core types

**Bottom-up approach**:
```
strace output → tracer → parser → data models → tracker → classifier → reporter → CLI
```

Each component can be tested independently before integration.