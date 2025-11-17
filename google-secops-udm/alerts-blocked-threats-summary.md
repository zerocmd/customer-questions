# Blocked Threats Summary

## Description
Summarizes threats that were successfully blocked by endpoint protection, showing effectiveness of prevention controls.

## Data Sources
Endpoint Detection and Response (EDR) Alerts
- CrowdStrike (add `metadata.log_type = "CS_DETECTS"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Threat Hunting (no variables)

## UDM Query
```
events:
  (security_result.action = "BLOCK" or security_result.action = "QUARANTINE")
  security_result.threat_name != ""

match:
  security_result.threat_name by 1d

outcome:
  $block_count = count(security_result.threat_name)
  $affected_hosts = count_distinct(principal.hostname)
  $host_list = array_distinct(principal.hostname)
  $severities = array_distinct(security_result.severity)
  $file_hashes = array_distinct(target.file.sha256)

order:
  $affected_hosts desc

limit:
  200
```

## Detection Logic
- Filters for BLOCK or QUARANTINE actions
- Groups by threat name per day
- Counts blocks and affected systems
- Collects severity distribution

## Output Fields
- `security_result.threat_name` - Blocked threat
- `$block_count` - Times blocked
- `$affected_hosts` - Number of hosts protected
- `$host_list` - Affected hostnames
- `$severities` - Threat severity levels
- `$file_hashes` - Blocked file hashes

## Use Cases
- Validate prevention effectiveness
- Identify recurring threats
- Report on security control performance
- Identify hosts requiring additional hardening
- Threat intelligence enrichment

## Metrics to Track
- Block rate by threat family
- Hosts with multiple blocks (potential targeting)
- Trending threats over time
- Prevention vs. detection ratio
