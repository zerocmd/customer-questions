# User Permission and Role Changes

## Description
Monitors changes to user permissions, roles, and group memberships to detect privilege escalation or unauthorized access modifications.

## Data Sources
Identity Provider (IDP)
- Okta (add `metadata.log_type = "OKTA"`)
- Entra ID (add `metadata.log_type = "AZURE_AD_AUDIT"`)

## Query Type
Threat Hunting (no variables)

## UDM Search
```
metadata.event_type = "USER_CHANGE_PERMISSIONS" OR metadata.event_type = "GROUP_MODIFICATION" OR metadata.product_event_type = /(?i)(add.*role|assign.*role|grant.*permission|add.*group|member.*add)/
```

## Detection Logic
- Captures USER_CHANGE_PERMISSIONS events
- Includes GROUP_MODIFICATION events
- Matches role/permission assignment patterns

## Output Fields
- `target.user.email_addresses` - Email address (Okta User Login, Entra User Principal Name) receiving permission changes
- `target.user.product_object_id` - User GUID (Okta User ID, Entra Object ID) receiving permission changes
- `principal.user.email_addresses` - Admin making the change
- `principal.user.product_object_id` - Admin GUID
- `principal.ip` - Source IP of admin
- `metadata.product_event_type` - Type of permission change
- `metadata.event_timestamp` - When the change occurred

## Use Cases
- Detect privilege escalation attempts
- Monitor admin group additions
- Track role assignments to sensitive groups
- Audit permission grants outside change windows
- Identify lateral movement via permission abuse
