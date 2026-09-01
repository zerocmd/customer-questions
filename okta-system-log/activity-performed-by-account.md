# Activity Performed by an Account

## Description
Returns every Okta System Log event where a single account was the actor, unfiltered by event type — the whole sequence of what that account did, in order, rather than one slice of it.

## Query Type
Investigation (with variable)

## Variables
- `OKTA_USER_LOGIN` - Okta user login to investigate (e.g., "jsmith@contoso.com")

## Okta System Log Filter
```
actor.alternateId eq "OKTA_USER_LOGIN"
```

## Detection Logic
- `actor.alternateId` is the login of the account that performed the action, so this returns what the account did, not what was done to it
- Changes made *to* the account — a factor reset, a group addition, a role grant — name it as the target instead, and are returned by the privilege and persistence questions
- Deliberately unscoped by `eventType`, so the ordering and adjacency of an account's events is preserved

## Output Fields
- `eventType` - Varies across the whole result set; the sequence of values is what the timeline is made of
- `displayMessage` - Human-readable summary, the fastest way to read a mixed-type result set
- `authenticationContext.externalSessionId` - Pivot into the session question
- `target.alternateId` / `target.displayName` - Meaning changes per event type; may be a user, group, application, or factor
- `outcome.reason` - Populated only on failures, and the field that distinguishes a credential failure from a policy denial

## Use Cases
- First-look triage on any alert naming an Okta account
- Reconstructing an authentication sequence as a sequence
- Establishing what an account did before and after a suspected compromise
- Sourcing session IDs, IPs, and application IDs for follow-on pivots
