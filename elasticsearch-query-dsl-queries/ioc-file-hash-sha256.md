# File Hash IOC Hunt (SHA256)

## Description
Hunts for a specific SHA256 file hash across the environment. Essential for determining the scope and spread of known-bad files identified through threat intelligence, malware analysis, or incident response.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `SHA256` - SHA256 hash to hunt for (64 character hex string)

## Elasticsearch Query DSL
```json
{"query_string":{"query":"sha256:SHA256"}}
```

## Detection Logic
- Matches alerts where the file hash equals the specified SHA256
- Simple and efficient direct hash lookup

## Output Fields
- `device.hostname` - Endpoint where file was observed
- `user_name` - User context
- `sha256` - File hash
- `process_details.filename` - File name
- `files_written.full_path` - File location on disk
- `tactic` - Associated MITRE tactic
- `technique_id` - Associated MITRE technique

## Use Cases
- Malware hash IOC hunting
- Threat intelligence validation
- Incident scoping (how many hosts have this file?)
- File timeline analysis (when did this file first appear?)

## Example
```
SHA256 = fc60c7aeb6af30d719410e6ec05a75761e5ccdf86a47e5d99a461915d9c9b270
```
