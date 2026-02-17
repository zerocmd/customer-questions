# Inbound Activity on Suspicious Ports

## Description
Hunts for inbound network connections on ports commonly targeted by attackers for remote access and control. These ports are frequently exploited to establish persistent access to compromised hosts.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Threat Hunting (no variables)

## Elasticsearch Query DSL
```json
{"query_string":{"query":"network_accesses.connection_direction:Inbound AND network_accesses.local_port:(22 OR 23 OR 3389 OR 5985 OR 5986 OR 445)"}}
```

## Detection Logic
- Requires inbound connection direction
- Matches any of these commonly-exploited ports:
  - 22 (SSH)
  - 23 (Telnet)
  - 3389 (RDP)
  - 5985 (WinRM HTTP)
  - 5986 (WinRM HTTPS)
  - 445 (SMB)

## Output Fields
- `device.hostname` - Target endpoint receiving the connection
- `network_accesses.local_port` - Port receiving the connection
- `network_accesses.remote_address` - Source IP of the connection
- `user_name` - User context
- `process_details.filename` - Process handling the connection

## High-Risk Indicators
- Inbound connections from external IPs
- Connections from unusual internal sources
- Activity outside business hours
- Multiple failed connections followed by success
- Connections from IPs in unusual geolocations

## Ports and Risks
| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Brute force, key theft |
| 23 | Telnet | Cleartext credentials, legacy systems |
| 3389 | RDP | BlueKeep, brute force, session hijacking |
| 5985/5986 | WinRM | Lateral movement, remote execution |
| 445 | SMB | EternalBlue, lateral movement, ransomware spread |

## MITRE ATT&CK Mapping
- T1021.001 - Remote Services: Remote Desktop Protocol
- T1021.002 - Remote Services: SMB/Windows Admin Shares
- T1021.004 - Remote Services: SSH
- T1021.006 - Remote Services: Windows Remote Management
