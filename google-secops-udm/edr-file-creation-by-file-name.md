# File Creation/Modification by Filename

## Description
Searches for creation or modification of files matching a specific name or pattern, useful for tracking malware artifacts or suspicious file activity.

## Data Sources
Endpoint Detection and Response (EDR)
- CrowdStrike (add `metadata.log_type = "CS_EDR"`)
- Palo Alto Cortex XDR (add `metadata.log_type = "CORTEX_XDR"`)

## Query Type
Investigation (with variable)

## Variables
- `$FILE_NAME` - Filename or pattern to search for (supports regex)

## UDM Query
```
(metadata.event_type = "FILE_CREATION" OR metadata.event_type = "FILE_MODIFICATION")
re.regex(target.file.full_path, `(?i)$FILE_NAME`)

match:
  principal.hostname, target.file.full_path

outcome:
  $event_count = count(target.file.full_path)
  $processes = array_distinct(principal.process.file.full_path)
  $users = array_distinct(principal.user.userid)
  $file_hashes = array_distinct(target.file.sha256)

order:
  metadata.event_timestamp.seconds desc

limit:
  300
```

## Detection Logic
- Searches for FILE_CREATION and FILE_MODIFICATION events
- Uses regex matching for flexible file name searches
- Groups by hostname and file path
- Captures creating process and user

## Output Fields
- `principal.hostname` - Endpoint where file was created
- `target.file.full_path` - Full file path
- `$event_count` - Number of times created/modified
- `$processes` - Processes that created/modified file
- `$users` - Users involved
- `$file_hashes` - SHA256 hashes

## Usage Examples

### Search for specific filename:
```
$FILE_NAME = "malware\.exe"
```

### Search for file extension:
```
$FILE_NAME = ".*\.docm$"  # Macro-enabled documents
```

### Search for files in specific directory:
```
$FILE_NAME = "C:\\\\Windows\\\\Temp\\\\.*\.bat"
```

### Search for known malware artifacts:
```
$FILE_NAME = "(beacon|cobalt|mimikatz)"
```

## Common Suspicious Files
- `.exe`, `.dll`, `.scr` in temp folders
- `.vbs`, `.js`, `.bat` scripts
- `.docm`, `.xlsm` macro documents
- Files with double extensions
