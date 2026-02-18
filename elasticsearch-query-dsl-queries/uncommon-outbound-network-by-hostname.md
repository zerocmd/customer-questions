# Uncommon Outbound Network Activity by Hostname

## Description
Investigates globally uncommon outbound network activity from a specific endpoint. Uses CrowdStrike's global prevalence enrichment to identify connections that are rare across the entire CrowdStrike customer base, which may indicate command and control communication or data exfiltration.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `HOSTNAME` - Endpoint hostname to investigate

## Elasticsearch Query DSL
```json
{"query_string":{"query":"_exists_:network_accesses.remote_address AND device.hostname:HOSTNAME AND network_accesses.connection_direction:Outbound AND global_prevalence:(low OR unique)"}}
```

## Detection Logic
- Requires network activity with a remote address
- Filters to specific hostname
- Requires outbound connection direction
- Matches low or unique global prevalence (rare across CrowdStrike telemetry)

## Output Fields
- `device.hostname` - Endpoint hostname
- `network_accesses.remote_address` - Destination IP
- `network_accesses.remote_port` - Destination port
- `global_prevalence` - Rarity indicator (low, unique, common)
- `process_details.filename` - Process making the connection
- `user_name` - User context

## Use Cases
- Command and control (C2) detection
- Data exfiltration investigation
- Compromised host triage
- Unusual beaconing activity detection

## Global Prevalence Values
- `unique` - Never seen before across CrowdStrike
- `low` - Rarely seen across CrowdStrike
- `common` - Frequently seen (likely benign)
