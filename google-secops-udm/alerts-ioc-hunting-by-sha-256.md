# File Hash IOC Hunting in Alerts

## Description
Searches for specific file hash IOCs across endpoint security alerts to identify spread of known malware.

## Data Sources
Endpoint Detection and Response (EDR) Alerts
- CrowdStrike (add `metadata.log_type = "CS_DETECTS"` or `metadata.log_type = "CS_EDR"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Investigation (with variable)

## Variables
- `SHA_256` - SHA256, SHA1, or MD5 hash to hunt for


## UDM Search
```
hash = "SHA_256"
```

## Detection Logic
- Searches for hash in file, process, and target process fields
- Returns all matching events for timeline analysis

## Output Fields
- `principal.hostname` - Affected endpoint
- `principal.user.userid` - User associated with event
- `target.file.full_path` - File location on disk
- `target.file.sha256` - File hash
- `security_result.threat_name` - How EDR/XDR classified it
- `security_result.severity` - Alert severity level
- `security_result.action` - Automated response taken

## Usage Examples

### Known Malware Hash
`$SHA_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`


### Hash from Threat Intel Feed
`$SHA_256 = "[HASH_FROM_FEED]"`


### Bulk Hash Hunting
For multiple hashes, use:
`(hash = /hash1|hash2|hash3/)`


## IOC Sources
- Threat intelligence feeds
- Malware analysis reports
- Security vendor IOC lists
- ISAC/ISAO sharing communities
- VirusTotal, Any.run, Hybrid Analysis

## Investigation Workflow
1. Identify scope: How many hosts affected?
2. Timeline: When was hash first/last seen?
3. Delivery: How did file arrive? (email, download, lateral movement)
4. Execution: Did file run? What did it do?
5. Containment: Were all instances blocked/removed?
6. Remediation: Clean all affected hosts
7. Prevention: Update signatures, block at perimeter
