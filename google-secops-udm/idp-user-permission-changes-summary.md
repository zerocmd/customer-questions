# User Permission and Role Changes

## Description
Monitors changes to user permissions, roles, and group memberships to detect privilege escalation or unauthorized access modifications.

## Data Sources
Identity Provider (IDP)
- Okta (add `metadata.log_type = "OKTA"`)
- Entra ID (add `metadata.log_type = "AZURE_AD_AUDIT"`)

## Query Type
Threat Hunting (no variables)

## UDM Query
```
(metadata.event_type = "USER_CHANGE_PERMISSIONS" OR
 metadata.event_type = "GROUP_MODIFICATION" OR
 metadata.product_event_type = /(?i)(add.*role|assign.*role|grant.*permission|add.*group|member.*add)/)

match:
  target.user.product_object_id, target.user.email_addresses by 1h

outcome:
  $change_count = count(target.user.email_addresses)
  $admins_logins = array_distinct(principal.user.email_addresses)
  $admins_ids = array_distinct(principal.user.product_object_id)
  $event_types = array_distinct(metadata.product_event_type)
  $admin_ips = array_distinct(principal.ip)

order:
  $change_count desc

limit:
  100
```

## Detection Logic
- Captures USER_CHANGE_PERMISSIONS events
- Includes GROUP_MODIFICATION events
- Matches role/permission assignment patterns
- Groups by target user per hour
- Identifies admins making changes

## Output Fields
- `target.user.email_addresses` - Email address (Okta User Login, Entra User Principal Name) receiving permission changes
- `target.user.product_object_id` - User GUID (Okta User ID, Entra Object ID) receiving permission changes
- `$change_count` - Number of changes per hour
- `$admins_logins`, `$admins_ids` - Admins making changes (email and GUID)
- `$event_types` - Types of permission changes
- `$admin_ips` - Source IPs of changes

## Use Cases
- Detect privilege escalation attempts
- Monitor admin group additions
- Track role assignments to sensitive groups
- Audit permission grants outside change windows
- Identify lateral movement via permission abuse
