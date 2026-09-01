# Identity Provider Changes and Federated Sign-ins

## Description
Returns identity provider creation and activation events alongside authentications that flowed through an identity provider, so a newly added federation path and its subsequent use are visible in one result set.

## Query Type
Threat Hunting (no variables)

## Okta System Log Filter
```
(eventType eq "system.idp.lifecycle.create" or eventType eq "system.idp.lifecycle.activate" or eventType eq "user.authentication.auth_via_IDP")
```

## Detection Logic
- Returns all three event types independently — the filter does not correlate them, so an identity provider being created and an authentication through it arrive as separate results
- Organization-wide with no parameter, so it returns every occurrence in the window rather than those tied to one account
- A federated identity provider survives password resets and MFA re-enrollment, because authentication no longer happens against the credential that was rotated

## Output Fields
- `eventType` - Separates identity provider changes from authentications through one
- `target.id` / `target.displayName` - The identity provider; the same value appearing in both a lifecycle event and an authentication is what ties the two together
- `actor.alternateId` - Who created the identity provider, and separately who authenticated through it
- `published` - Ordering carries the finding; creation followed by authentication is the pattern

## Use Cases
- Detecting federated persistence following an administrative compromise
- Finding authentication paths that survive credential rotation
- Reviewing identity provider changes against approved federation work
- Identity-focused intrusion tradecraft used by groups such as Scattered Spider
