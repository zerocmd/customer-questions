# Token, Consent, and Factor Persistence for an Account

## Description
Returns three classes of access that outlive a password reset for one account: API tokens and OAuth client credentials it created, admin consent it granted, and authenticator enrollments and resets made against it by anyone.

## Query Type
Investigation (with variable)

## Variables
- `OKTA_USER_LOGIN` - Okta user login to check (e.g., "jsmith@contoso.com")

## Okta System Log Filter
```
((eventType eq "system.api_token.create" or eventType eq "app.oauth2.credentials.lifecycle.create" or eventType eq "app.oauth2.admin.consent.grant") and actor.alternateId eq "OKTA_USER_LOGIN") or (eventType sw "user.mfa.factor" and target.alternateId eq "OKTA_USER_LOGIN")
```

## Detection Logic
- Each mechanism survives credential rotation: API tokens and OAuth credentials do not re-authenticate, admin consent persists against the application, and an enrolled authenticator keeps MFA satisfied
- Two scopings in one query, because the mechanisms differ in who performs them — tokens, credentials, and consent are created **by** the account, while an authenticator is enrolled **on** the account, often by an administrator rather than the user
- The target-scoped half covers an administrator enrolling a factor on the account; an actor-scoped query alone would not return it
- `eventType sw "user.mfa.factor"` covers enrollment, reset, deactivation, and update
- Federated identity providers are also a persistence route and are not covered here — see the identity provider question for that path

## Output Fields
- `eventType` - Names which mechanism was created, and therefore what has to be revoked to close it
- `actor.alternateId` - On a factor result, an actor other than the account itself is the administrative-enrollment case
- `target.displayName` / `target.id` - The token, OAuth client, application, or factor to revoke
- `published` - Position relative to the containment action decides whether this is pre-existing or attacker-established

## Use Cases
- Post-containment verification that a password reset closed access
- Detecting attacker-established persistence after credential compromise
- Catching authenticators enrolled on an account by someone else
- Standard closing step for any Okta account compromise investigation
