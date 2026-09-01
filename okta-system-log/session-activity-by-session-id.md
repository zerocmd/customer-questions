# Every Event in One Okta Session

## Description
Returns every System Log event carrying a single Okta session identifier — everything the account did after that sign-in, not just the sign-in itself.

## Query Type
Investigation (with variable)

## Variables
- `OKTA_SESSION_ID` - Okta external session identifier to investigate
  - Sourced from `authenticationContext.externalSessionId` on any event in the account or source IP question

## Okta System Log Filter
```
authenticationContext.externalSessionId eq "OKTA_SESSION_ID"
```

## Detection Logic
- `externalSessionId` is stable across every event a session generates, so filtering on it narrows an investigation to one session
- Matches that one identifier only; a session chained to a parent carries the parent in `rootSessionId`, and those events are not returned by this filter
- Events with no `authenticationContext`, such as system-generated activity, carry no session identifier and never match

## Output Fields
- `eventType` - The ordered sequence within the session is the finding, not any single value
- `authenticationContext.rootSessionId` - A value differing from the session ID queried means a parent session holds more of the activity; query it separately
- `target.alternateId` / `target.displayName` - What was reached during the session
- `displayMessage` - Human-readable summary across a mixed-type result set
- `transaction.id` - Correlates the multiple events a single action can emit

## Use Cases
- Reconstructing what an account did within one session
- Separating a single suspicious session from an account's normal activity
- Scoping application and data access that followed a compromised sign-in
- Pivot target from the account and source IP questions
