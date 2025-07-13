# Capsule Runtime V2 - Implementation Progress

## ✅ Phase 1: Core Foundation (COMPLETED)

### Core Data Models ✅
- [x] ProcessEvent with spawn/exit event types
- [x] ProcessLabel classification (Agent, Tool, SystemTool, Unknown)  
- [x] AgentWorkflow enum with 7 process-based patterns
- [x] ProcessTree for real-time hierarchical tracking with anyhow::Result
- [x] Workflow classification from command line patterns
- [x] All core types exported from core/src/lib.rs

### Trace Crate ✅ 
- [x] Linux strace subprocess management
- [x] Raw strace line streaming (no parsing)
- [x] Process-only syscall filtering via strace flags
- [x] Cancellation support and graceful cleanup
- [x] Clean separation from parsing logic

### Parse Crate ✅
- [x] Enhanced regex parsing with named capture groups
- [x] StraceEvent types moved from trace/ crate
- [x] Support for any syscall type (flexible parsing)
- [x] Process-only filtering via is_process_event()
- [x] All parsing tests passing

### Track Crate ✅
- [x] StraceEvent → ProcessEvent conversion with timestamp handling
- [x] Real-time ProcessTree updates using core/ types
- [x] PID→PPID relationship tracking via HashMap
- [x] JSONL file streaming for ProcessEvent persistence
- [x] Tokio async with broadcast channels and cancellation
- [x] Process-only filtering and lifecycle management

## 🔄 Phase 2: CLI Integration (NEXT PRIORITY)

### CLI Orchestration (IMMEDIATE NEXT)
- [ ] Main CLI entry point with clap argument parsing
- [ ] Session directory creation (~/.capsule/runs/timestamp/)
- [ ] Tokio pipeline coordination with JoinSet
- [ ] Broadcast channel setup and distribution
- [ ] Ready synchronization between pipeline stages
- [ ] Graceful shutdown with cancellation tokens
- [ ] Basic `run` command implementation
- [ ] Error handling and recovery across pipeline

### Integration Testing
- [ ] End-to-end pipeline test (trace → parse → track)
- [ ] Verify ProcessEvent flow and tree building
- [ ] Test cancellation and cleanup behavior
- [ ] Validate JSONL output format

## ⚙️ Phase 3: Infrastructure & Polish (LATER)

### Session Management Enhancement
- [ ] Session metadata file creation
- [ ] Multiple output streams (raw.jsonl, tree.json)
- [ ] Session cleanup and archival policies
- [ ] Configuration file support

### Architecture Verification
- [ ] Verify JoinSet usage matches v2.md spec
- [ ] Validate structured concurrency patterns
- [ ] Performance testing and optimization
- [ ] Memory usage monitoring

### Reporting & CLI Commands
- [ ] `report` command for session analysis
- [ ] Human-readable tree output
- [ ] Session listing and management
- [ ] Export capabilities

## Current Architecture Status

```
CLI → trace (raw strace) → parse (StraceEvent) → track (ProcessEvent + ProcessTree)
 ↓                         ↓                      ↓
session mgmt           regex parsing         tree management + events.jsonl
(NEXT)                 ✅ COMPLETE           ✅ COMPLETE
```

## Implementation Strategy

**All core pipeline components complete** - trace, parse, track working independently.

**Next Goal**: Wire up CLI orchestration to create working end-to-end pipeline.

**CLI will handle**:
1. Session directory creation
2. ProcessTracker instantiation  
3. Tokio task coordination
4. User interface and commands

## Session Goal

Complete CLI orchestration to achieve first working end-to-end process tracking session.