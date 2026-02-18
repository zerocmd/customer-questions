# Execution Activity by Username

## Description
Investigates execution-related activity for a specific user account. Focuses on alerts tagged with the MITRE ATT&CK "Execution" tactic to identify potentially unauthorized code execution in the context of a specific user.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `USER_NAME` - Username to investigate (e.g., "jsmith", "admin")

## Elasticsearch Query DSL
```json
{"query_string":{"query":"tactic:Execution AND user_name:USER_NAME"}}
```

## Detection Logic
- Filters for alerts with MITRE ATT&CK Execution tactic
- Matches the specified username
- Returns execution-related detections for that user

## Output Fields
- `device.hostname` - Endpoint where execution occurred
- `user_name` - User account context
- `tactic` - MITRE ATT&CK tactic
- `technique` - MITRE ATT&CK technique
- `technique_id` - MITRE technique ID (e.g., T1059)
- `process_details.filename` - Executed file
- `cmdline` - Command line arguments

## Use Cases
- Compromised account investigation
- Insider threat investigation
- Privilege escalation detection
- Post-incident user activity analysis
