# Network Connection Activity by IP Address

## Description
Investigates outbound network connection activity to a specific IP address. Useful for hunting known-bad IP indicators from threat intelligence feeds or identifying connections to command and control infrastructure.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `REMOTE_ADDRESS` - IP address to hunt for in network connections

## Elasticsearch Query DSL
```json
{"query_string":{"query":"network_accesses.remote_address:REMOTE_ADDRESS"}}
```

## Detection Logic
- Matches network connection events where the remote address matches the specified IP
- Returns alerts containing network activity to the target IP

## Output Fields
- `device.hostname` - Endpoint that initiated the connection
- `user_name` - User context for the connection
- `network_accesses.remote_address` - Destination IP address
- `network_accesses.remote_port` - Destination port
- `network_accesses.connection_direction` - Inbound or Outbound

## Use Cases
- Threat intelligence IOC hunting
- Command and control (C2) infrastructure investigation
- Post-incident scoping to identify affected hosts
- Validating threat feed indicators in environment
