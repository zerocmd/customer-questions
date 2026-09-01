# Session Start Failures from a Source IP

## Description
Returns failed sign-in attempts from a single source IP at the session start stage, where Okta evaluates credentials and decides whether to issue a session. This is the password-spray shape: one address, repeated failures, spread across many accounts.

## Query Type
Investigation (with variable)

## Variables
- `IP_ADDRESS` - Source IP address to investigate (e.g., "203.0.113.24")

## Okta System Log Filter
```
eventType eq "user.session.start" and outcome.result eq "FAILURE" and client.ipAddress eq "IP_ADDRESS"
```

## Detection Logic
- `user.session.start` with `outcome.result eq "FAILURE"` captures attempts that did not establish a session
- This is one stage of authentication, not all of it: failures at the MFA stage (`user.authentication.auth_via_mfa`) and sign-on policy denials (`policy.evaluate_sign_on`) are separate event types and are not returned here
- A single credential failure can emit events at more than one stage, so counts here are session start attempts rather than total failure events

## Output Fields
- `actor.alternateId` - Distinct count across the result set is the spray signal, not the raw event count
- `outcome.reason` - Separates `INVALID_CREDENTIALS` from lockout and policy denial, which have different investigative meaning
- `client.userAgent.rawUserAgent` - Spray tooling typically reuses a single string across every attempt
- `authenticationContext.externalSessionId` - Pivot into the session question if any attempt from the address later succeeded

## Use Cases
- Password spray and credential stuffing investigation scoped to one source
- Measuring how many accounts a flagged IP attempted
- Establishing the pre-compromise failure timeline for an address that later succeeded
- Corroborating an alert raised by another identity or network source
