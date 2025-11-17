# Failed Login Attempts by User (IDP)

## Description
Detects multiple failed login attempts from identity providers that may indicate brute force or password spray attacks.

## Data Sources
Identity Provider (IDP)
- Okta (add `metadata.log_type = "OKTA"`)
- Entra ID (add `metadata.log_type = "AZURE_AD"` or `metadata.log_type = "AZURE_AD_SIGNIN"`)

## Query Type
Threat Hunting (no variables)

## UDM Query
```
events:
  metadata.event_type = "USER_LOGIN"
  security_result.action = "FAIL"
  $user = target.user.userid

match:
  $user over 10m

outcome:
  $failed_count = count($user)
  $unique_ips = count_distinct(principal.ip)
  $ip_list = array_distinct(principal.ip)

condition:
  $failed_count >= 5

dedup:
  $user

order:
  $failed_count desc

limit:
  100
```

## Detection Logic
- Looks for USER_LOGIN events with FAIL action
- Groups by user over 10-minute windows
- Triggers when 5 or more failures occur
- Tracks unique source IPs to identify distributed attacks

## Output Fields
- `$user` - User account targeted
- `$failed_count` - Number of failed attempts
- `$unique_ips` - Count of distinct source IPs
- `$ip_list` - List of source IP addresses
