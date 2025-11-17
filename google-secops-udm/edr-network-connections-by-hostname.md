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
- `$HOSTNAME` - Endpoint hostname to investigate

## UDM Query
```
metadata.event_type = "NETWORK_CONNECTION"
principal.hostname = "$HOSTNAME"
target.ip != ""

match:
  target.ip, target.port by 1h

outcome:
  $connection_count = count(target.ip)
  $processes = array_distinct(principal.process.file.full_path)
  $bytes_sent = sum(network.sent_bytes)
  $bytes_received = sum(network.received_bytes)
  $total_bytes = $bytes_sent + $bytes_received

order:
  $connection_count desc

limit:
  300
```

## Detection Logic
- Filters for NETWORK_CONNECTION events from specific host
- Excludes empty target IPs
- Groups by destination IP and port per hour
- Aggregates connection counts and data transfer volume

## Output Fields
- `target.ip` - Destination IP addresses
- `target.port` - Destination ports
- `$connection_count` - Number of connections
- `$processes` - Processes making connections
- `$total_bytes` - Total data transferred

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
