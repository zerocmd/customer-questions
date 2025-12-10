# PowerShell Execution Monitoring

## Description
Monitors PowerShell execution on endpoints, focusing on encoded commands, web downloads, and other suspicious patterns commonly used by attackers.

## Data Sources
Endpoint Detection and Response (EDR)
- CrowdStrike (add `metadata.log_type = "CS_EDR"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Threat Hunting (no variables)

## YARA-L 2.0
```
events:
  metadata.event_type = "PROCESS_LAUNCH"
  re.regex(principal.process.file.full_path, `(?i)powershell\.exe|pwsh\.exe`)
  (re.regex(principal.process.command_line, `(?i)(-enc|-encodedcommand|-w hidden|-windowstyle hidden|downloadstring|invoke-webrequest|invoke-restmethod|iex|invoke-expression|bitstransfer)`) OR
   re.regex(principal.process.command_line, `(?i)(bypass|unrestricted|-nop|-noprofile)`))

match:
  principal.hostname by 1h

outcome:
  $exec_count = count(principal.process.command_line)
  $command_lines = array_distinct(principal.process.command_line)
  $parent_processes = array_distinct(principal.process.parent_process.file.full_path)
  $users = array_distinct(principal.user.userid)

order:
  $exec_count desc

limit:
  150
```

## Detection Logic
- Detects PowerShell executions with suspicious parameters:
  - Encoded commands (-enc, -encodedcommand)
  - Hidden windows
  - Web download functions
  - Execution policy bypass
- Groups by hostname per hour
- Tracks parent processes and users

## Output Fields
- `principal.hostname` - Endpoint name
- `$exec_count` - Number of PowerShell executions
- `$command_lines` - Full command lines
- `$parent_processes` - Spawning processes
- `$users` - Users executing PowerShell

## High-Risk Indicators
- Base64 encoded commands
- Downloads from Internet
- Execution policy bypass
- Hidden window execution
- Non-interactive execution
