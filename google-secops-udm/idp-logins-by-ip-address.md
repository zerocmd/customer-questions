# Login Activity from Specific IP Address

## Description
Investigates all login attempts originating from a specific IP address, useful for tracking suspicious or known-malicious IPs.

## Data Sources
Identity Provider (IDP)
- Okta (add `metadata.log_type = "OKTA"`)
- Entra ID (add `metadata.log_type = "AZURE_AD_SIGNIN"`)

## Query Type
Investigation (with variable)

## Variables
- `IP_ADDRESS` - Source IP address to investigate

## UDM Search
```
metadata.event_type = "USER_LOGIN" AND principal.ip = "IP_ADDRESS" AND target.user.email_addresses != ""
```

## Detection Logic
- Filters for USER_LOGIN events from specific IP

## Output Fields
- `target.user.email_addresses` - Email address (Okta User Login, Entra User Principal Name)
- `target.user.product_object_id` - User GUID (Okta User ID, Entra Object ID)
- `security_result.action` - Success/failure status
- `network.http.user_agent` - User agent string
- `metadata.event_timestamp` - When the login occurred

## Usage Example
Replace `IP_ADDRESS` with known suspicious IP address
