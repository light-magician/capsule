# Capsule Supabase Database Setup

## Quick Start

1. **Start Services:**
   ```bash
   cd integration/
   docker-compose up -d
   ```

2. **Access Supabase Studio:** http://localhost:8000

3. **Database Connection Details:**
   - Host: localhost
   - Port: 54322
   - Database: postgres
   - Username: postgres
   - Password: postgres

## Schema Overview

### Tables

1. **`runs`** - Central table for run metadata
2. **`syscall_events`** - Individual syscall records from strace
3. **`actions`** - Aggregated high-level actions

### Views & Functions

- **`recent_runs`** - View showing runs sorted by recency with status
- **`get_latest_run()`** - Function to get most recent run UUID
- **`update_run_stats()`** - Function to recalculate run statistics

## Sample Queries for AI Testing

### Natural Language Query Examples

Try these in the Supabase Studio AI SQL Editor:

**1. "Show me all runs from the last day"**
```sql
SELECT * FROM recent_runs WHERE start_time > NOW() - INTERVAL '1 day';
```

**2. "Find all network events from the most recent run"**
```sql
SELECT se.* FROM syscall_events se 
JOIN recent_runs r ON se.run_id = r.id 
WHERE r.id = get_latest_run() 
AND se.network_info IS NOT NULL;
```

**3. "Show me all file operations with risk tags"**
```sql
SELECT run_id, syscall, operation, abs_path, risk_tags 
FROM syscall_events 
WHERE operation IN ('open', 'read', 'write', 'close') 
AND array_length(risk_tags, 1) > 0;
```

**4. "What processes spawned the most syscalls?"**
```sql
SELECT pid, exe_path, COUNT(*) as syscall_count 
FROM syscall_events 
GROUP BY pid, exe_path 
ORDER BY syscall_count DESC;
```

**5. "Show me high-risk activities"**
```sql
SELECT r.command_line, r.agent_type, se.syscall, se.risk_tags, se.abs_path
FROM syscall_events se
JOIN runs r ON se.run_id = r.id
WHERE array_length(se.risk_tags, 1) > 0
ORDER BY r.start_time DESC;
```

## Testing the Setup

1. **Verify Tables Exist:**
   ```sql
   SELECT table_name FROM information_schema.tables 
   WHERE table_schema = 'public';
   ```

2. **Check Sample Data:**
   ```sql
   SELECT * FROM recent_runs;
   ```

3. **Test AI Query:**
   Go to Supabase Studio → SQL Editor and ask:
   *"Show me all the runs and their command lines"*

## Schema Files

- `schema.sql` - Complete database schema with sample data
- `init.sql` - User/role setup for Supabase authentication

## Next Steps

1. **Implement `capsule send` command** to populate real run data
2. **Test AI query capabilities** in Supabase Studio
3. **Add more sophisticated risk analysis** queries
4. **Create dashboard views** for common queries