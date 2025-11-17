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
- `$IP_ADDRESS` - Source IP address to investigate

## UDM Query
```
metadata.event_type = "USER_LOGIN"
principal.ip = "$IP_ADDRESS"

match:
  target.user.email_addresses, target.user.product_object_id, security_result.action

outcome:
  $attempt_count = count(target.user.product_object_id)
  $user_agents = array_distinct(network.http.user_agent)

order:
  $attempt_count desc

limit:
  200
```

## Detection Logic
- Filters for USER_LOGIN events from specific IP
- Groups by user and action type
- Counts attempts per user
- Collects unique user agents

## Output Fields
- `target.user.email_addresses` - Email address (Okta User Login, Entra User Principal Name)
- `target.user.product_object_id` - User GUID (Okta User ID, Entra Object ID)
- `security_result.action` - Success/failure status
- `$attempt_count` - Number of attempts per user
- `$user_agents` - List of user agents used

## Usage Example
Replace `$IP_ADDRESS` with known suspicious IP address
