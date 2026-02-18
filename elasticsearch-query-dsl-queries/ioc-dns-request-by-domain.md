# DNS Request Activity by Domain

## Description
Investigates DNS request activity for a specific domain, including subdomains. Useful for hunting known-bad domains from threat intelligence or identifying communication with attacker-controlled infrastructure.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Investigation (with variable)

## Variables
- `DOMAIN` - Domain name to hunt for (e.g., "evil.com")

## Elasticsearch Query DSL
```json
{"query_string":{"query":"dns_requests.domain_name:(DOMAIN OR *DOMAIN)"}}
```

## Detection Logic
- Matches exact domain name via `match` clause
- Matches subdomains via `wildcard` clause (e.g., "sub.evil.com" matches "*evil.com")
- Returns alerts containing DNS requests to the target domain or its subdomains

## Output Fields
- `device.hostname` - Endpoint that made the DNS request
- `user_name` - User context
- `dns_requests.domain_name` - Queried domain name
- `process_details.filename` - Process that initiated the request

## Use Cases
- Threat intelligence domain IOC hunting
- Command and control domain investigation
- Phishing domain identification
- DGA (Domain Generation Algorithm) domain hunting
