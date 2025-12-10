# Network Connections from Specific Host

## Description
Investigates all network connections originating from a specific endpoint, useful for investigating compromised hosts or data exfiltration.

## Data Sources
Endpoint Detection and Response (EDR)
- CrowdStrike (add `metadata.log_type = "CS_EDR"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Investigation (with variable)

## Variables
- `HOSTNAME` - Endpoint hostname to investigate

## UDM Search
```
metadata.event_type = "NETWORK_CONNECTION" AND principal.hostname = "HOSTNAME" AND target.ip != ""
```

## Detection Logic
- Filters for NETWORK_CONNECTION events from specific host
- Excludes empty target IPs

## Output Fields
- `target.ip` - Destination IP address
- `target.port` - Destination port
- `principal.process.file.full_path` - Process making connection
- `network.sent_bytes` - Bytes sent
- `network.received_bytes` - Bytes received
- `metadata.event_timestamp` - When the connection occurred

## Use Cases
- Investigate suspected compromised host
- Track data exfiltration
- Identify C2 communication
- Analyze network behavior patterns
- Identify beaconing activity

## Enhancements
Add geographic filtering:
```
principal.ip_geo_artifact.location.country_or_region != ""
```
