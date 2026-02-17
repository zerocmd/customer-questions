# PowerShell Unsafe Execution Hunt

## Description
Hunts for PowerShell executions using unsafe or evasive options commonly associated with fileless malware, living-off-the-land attacks, and post-exploitation frameworks. Focuses on encoded commands, execution policy bypass, and hidden window execution.

## Data Sources
CrowdStrike Falcon Alerts via Elastic
- Index pattern: `logs-crowdstrike.alert-*`

## Query Type
Threat Hunting (no variables)

## Elasticsearch Query DSL
```json
{"query_string":{"query":"cmdline:*powershell* AND cmdline:(*-enc* OR *-encodedcommand* OR *bypass* OR *-nop* OR *downloadstring*)","analyze_wildcard":true}}
```

## Detection Logic
- Requires PowerShell in the command line
- Matches any of these unsafe patterns:
  - `-enc` or `-encodedcommand` - Base64 encoded command execution
  - `bypass` - Execution policy bypass
  - `-windowstyle hidden` - Hidden window execution
  - `-nop` or `-noprofile` - No profile execution
  - `downloadstring` - Web content download and execution

## Output Fields
- `device.hostname` - Endpoint where PowerShell ran
- `user_name` - User who executed PowerShell
- `cmdline` - Full command line (examine for encoded payload)
- `parent_details.filename` - Parent process
- `tactic` - Associated MITRE tactic
- `technique_id` - Associated MITRE technique

## High-Risk Indicators
- Base64 encoded commands (decode to analyze payload)
- Download cradles (DownloadString, DownloadFile, IEX)
- Execution policy bypass combined with hidden windows
- Non-interactive execution from unusual parents (cmd, wscript, mshta)

## MITRE ATT&CK Mapping
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1027 - Obfuscated Files or Information
- T1140 - Deobfuscate/Decode Files or Information
