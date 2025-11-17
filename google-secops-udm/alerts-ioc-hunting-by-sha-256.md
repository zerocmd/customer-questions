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
- `$SHA_256` - SHA256, SHA1, or MD5 hash to hunt for


## UDM Query
```
(hash = "$SHA_256")

match:
  principal.hostname

outcome:
  $detection_count = count(principal.hostname)
  $threat_names = array_distinct(security_result.threat_name)
  $file_paths = array_distinct(target.file.full_path)
  $severities = array_distinct(security_result.severity)
  $actions = array_distinct(security_result.action)
  $users = array_distinct(principal.user.userid)

order:
  metadata.event_timestamp.seconds desc

limit:
  500
```

## Detection Logic
- Searches for hash in file, process, and target process fields
- Groups by affected hostname
- Collects threat classification and file locations
- Chronological ordering for timeline analysis

## Output Fields
- `principal.hostname` - Affected endpoints
- `$detection_count` - Detections per host
- `$threat_names` - How EDR/XDR classified it
- `$file_paths` - File locations on disk
- `$severities` - Alert severity levels
- `$actions` - Automated responses
- `$users` - Users associated with file

## Usage Examples

### Known Malware Hash
```
$SHA_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

### Hash from Threat Intel Feed
```
$SHA_256 = "[HASH_FROM_FEED]"
```

### Bulk Hash Hunting
For multiple hashes, use:
```
(hash = /hash1|hash2|hash3/)
```

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
