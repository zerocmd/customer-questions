# MITRE ATT&CK Technique Activity

## Description
Investigates all activity matching a specific MITRE ATT&CK technique ID. Enables focused hunting or investigation based on threat intelligence, red team findings, or specific attack techniques of concern.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `TECHNIQUE_ID` - MITRE ATT&CK technique ID (e.g., "T1059", "T1003", "T1078")

## Elasticsearch Query DSL
```json
{"query_string":{"query":"technique_id:TECHNIQUE_ID"}}
```

## Detection Logic
- Matches alerts tagged with the specified MITRE technique ID
- Returns all detections associated with that technique

## Output Fields
- `device.hostname` - Affected endpoint
- `user_name` - User context
- `technique_id` - MITRE technique identifier
- `technique` - Technique name
- `tactic` - Associated tactic
- `process_details.filename` - Process involved
- `cmdline` - Command line

## Use Cases
- Threat intel-driven hunting (hunt for techniques used by specific threat actors)
- Red team finding validation
- Gap analysis (are we detecting this technique?)
- Incident investigation (find all instances of a technique)

## Common Technique IDs
| ID | Name |
|----|------|
| T1059 | Command and Scripting Interpreter |
| T1003 | OS Credential Dumping |
| T1078 | Valid Accounts |
| T1021 | Remote Services |
| T1053 | Scheduled Task/Job |
| T1055 | Process Injection |
| T1071 | Application Layer Protocol |
| T1105 | Ingress Tool Transfer |

## MITRE ATT&CK Reference
https://attack.mitre.org/techniques/
