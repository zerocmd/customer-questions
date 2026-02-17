# Process Activity by Parent Hash

## Description
Investigates all process activity spawned by a specific parent process identified by its SHA256 hash. Useful for tracking the behavior of a known-bad executable or understanding the full scope of a compromised process's child activity.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `PARENT_SHA256` - SHA256 hash of the parent process to investigate

## Elasticsearch Query DSL
```json
{"query_string":{"query":"parent_details.sha256:PARENT_SHA256"}}
```

## Detection Logic
- Matches alerts where the parent process hash equals the specified SHA256
- Returns all child process activity from that parent

## Output Fields
- `device.hostname` - Endpoint where activity occurred
- `user_name` - User context
- `parent_details.sha256` - Parent process hash
- `parent_details.filename` - Parent process name
- `parent_details.cmdline` - Parent command line
- `process_details.filename` - Child process name
- `cmdline` - Child process command line

## Use Cases
- Malware behavior analysis (what did this malware spawn?)
- Living-off-the-land binary abuse detection
- Process injection investigation
- Full attack chain reconstruction

## Investigation Workflow
1. Identify a known-bad hash from threat intel or detection
2. Search for all child process activity from that hash
3. Analyze spawned processes for additional IOCs
4. Check for persistence mechanisms or lateral movement
