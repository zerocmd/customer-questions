# High Severity Alerts Summary

## Description
Aggregates high and critical severity alerts from endpoint security tools to provide a prioritized view of security threats.

## Data Sources
Endpoint Detection and Response (EDR) Alerts
- CrowdStrike (add `metadata.log_type = "CS_EDR"` or `metadata.log_type = "CS_DETECTS"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Threat Hunting (no variables)

## YARA-L 2.0
```
events:
  (metadata.log_type = "CS_EDR" OR metadata.log_type = "CS_DETECTS" OR metadata.log_type = "CORTEX_XDR")
  (security_result.severity = "HIGH" OR security_result.severity = "CRITICAL")

match:
  security_result.threat_name, principal.hostname by 1h

outcome:
  $alert_count = count(security_result.threat_name)
  $affected_hosts = count_distinct(principal.hostname)
  $host_list = array_distinct(principal.hostname)
  $actions_taken = array_distinct(security_result.action)

order:
  $alert_count desc

limit:
  100
```

## Detection Logic
- Filters for HIGH and CRITICAL severity alerts
- Groups by threat name and hostname per hour
- Counts total alerts and affected hosts
- Tracks remediation actions

## Output Fields
- `security_result.threat_name` - Threat/detection name
- `principal.hostname` - Affected endpoints
- `$alert_count` - Number of alerts
- `$affected_hosts` - Count of unique hosts
- `$host_list` - List of affected hostnames
- `$actions_taken` - EDR/XDR actions (BLOCK, QUARANTINE, ALLOW)

## Use Cases
- Daily security posture review
- Incident prioritization
- Threat trending analysis
- Executive reporting
