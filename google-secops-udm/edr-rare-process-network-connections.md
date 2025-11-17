# Rare Process Network Connections

## Description
Identifies processes making outbound network connections that rarely communicate externally, potentially indicating malware or compromised legitimate processes.

## Data Source
Endpoint Detection and Response (EDR)
- CrowdStrike (add `metadata.log_type = "CS_EDR"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Threat Hunting (no variables)

## UDM Query
```
events:
  metadata.event_type = "NETWORK_CONNECTION"
  principal.process.file.full_path != ""
  target.ip != ""
  NOT re.regex(principal.process.file.full_path, `(?i)(chrome\.exe|firefox\.exe|msedge\.exe|teams\.exe|outlook\.exe|onedrive\.exe)`)

match:
  principal.process.file.full_path over 24h

outcome:
  $unique_hosts = count_distinct(principal.hostname)
  $unique_destinations = count_distinct(target.ip)
  $connection_count = count(target.ip)
  $destination_ips = array_distinct(target.ip)

condition:
  $unique_hosts <= 3 AND $connection_count >= 5

order:
  $unique_destinations desc

limit:
  100
```

## Detection Logic
- Finds processes making external connections
- Excludes common browsers and business apps
- Groups by process name over 24 hours
- Triggers on processes seen on ≤3 hosts but with ≥5 connections
- Identifies rare/unusual network activity

## Output Fields
- `principal.process.file.full_path` - Unusual process
- `$unique_hosts` - Number of hosts running it
- `$unique_destinations` - Different IPs contacted
- `$connection_count` - Total connections
- `$destination_ips` - List of destination IPs

## Indicators of Compromise
- System processes making unexpected connections
- LOLBins (Living Off the Land Binaries) with network activity
- Rare executables with high connection counts
- Processes from suspicious directories

## Tuning
Adjust exclusion list for your environment's normal applications.
