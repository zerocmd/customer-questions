# File Activity by Filename

## Description
Investigates file write and access activity for a specific filename. Useful for hunting known malware filenames, sensitive document access, or tracking the spread of specific files across the environment.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `FILENAME` - Filename to search for (e.g., "mimikatz.exe", "passwords.xlsx")

## Elasticsearch Query DSL
```json
{"query_string":{"query":"files_written.filename:FILENAME OR files_accessed.filename:FILENAME"}}
```

## Detection Logic
- Matches files written with the specified filename
- Matches files accessed with the specified filename
- Requires at least one match (file write OR file access)

## Output Fields
- `device.hostname` - Endpoint where file activity occurred
- `user_name` - User who performed the activity
- `files_written.filename` - Written file name
- `files_written.full_path` - Full path of written file
- `files_accessed.filename` - Accessed file name
- `process_details.filename` - Process that performed the operation

## Use Cases
- Known malware filename hunting (e.g., "mimikatz.exe", "procdump.exe")
- Sensitive file access monitoring
- Data exfiltration investigation
- Ransomware file activity tracking

## Common Filenames to Hunt
- `mimikatz.exe` - Credential dumping tool
- `procdump.exe` - Process dumping utility
- `psexec.exe` - Remote execution tool
- `nc.exe`, `ncat.exe` - Netcat variants
