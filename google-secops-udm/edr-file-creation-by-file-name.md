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
- `FILE_NAME` - Filename or pattern to search for (supports regex)

## UDM Search
```
(metadata.event_type = "FILE_CREATION" OR metadata.event_type = "FILE_MODIFICATION") AND target.file.full_path = /(?i)FILE_NAME/
```

## Detection Logic
- Searches for FILE_CREATION and FILE_MODIFICATION events
- Uses regex matching for flexible file name searches

## Output Fields
- `principal.hostname` - Endpoint where file was created
- `principal.user.userid` - User who created/modified file
- `principal.process.file.full_path` - Process that created/modified file
- `target.file.full_path` - Full file path
- `target.file.sha256` - File hash
- `metadata.event_timestamp` - When the event occurred

## Usage Examples

### Search for specific filename:
`$FILE_NAME = "malware\.exe"`

### Search for file extension:
`$FILE_NAME = ".*\.docm$"  # Macro-enabled documents`

### Search for files in specific directory:
`$FILE_NAME = "C:\\\\Windows\\\\Temp\\\\.*\.bat"`

### Search for known malware artifacts:
`$FILE_NAME = "(beacon|cobalt|mimikatz)"`

## Common Suspicious Files
- `.exe`, `.dll`, `.scr` in temp folders
- `.vbs`, `.js`, `.bat` scripts
- `.docm`, `.xlsm` macro documents
- Files with double extensions
