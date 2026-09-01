# Events Targeting One Application

## Description
Returns the events that name a single Okta application as their target — created, policies mapped, groups assigned, users provisioned, access failures, deactivated — so its lifecycle reads as one sequence.

## Query Type
Investigation (with variable)

## Variables
- `OKTA_APPLICATION_ID` - Okta application instance ID to investigate (e.g., "0oa1b2c3d4EXAMPLE")
  - Sourced from `target.id` on any application event

## Okta System Log Filter
```
target.id eq "OKTA_APPLICATION_ID" and target.type eq "AppInstance"
```

## Detection Logic
- `target.id` appears on every event where the application is the object of the action, regardless of event type
- `target.type eq "AppInstance"` constrains results to events involving an application; `target.id` on its own matches users, groups, policy rules, and authenticator enrollments equally
- `target` is an array and the two clauses are evaluated across it independently, so an event carrying both a user target and an application target satisfies both — the type clause narrows the result set rather than binding the identifier to an application
- Target-scoped, so events where the application is the *actor* rather than the object — OAuth and API activity performed by the app itself — are not returned
- Returns creation, policy mapping, group and user assignment, provisioning, authentication failures, and deactivation together

## Output Fields
- `eventType` - Marks the lifecycle stage; the span from create to deactivate is the finding
- `target` - An array, so events that touch both a user and the application appear here too; this is what links provisioning activity to the app
- `outcome.reason` - Carries the reason on SAML and integration authentication failures, which is where unauthorized access attempts surface
- `debugContext.debugData` - Policy, provisioning, and risk detail specific to each lifecycle event
- `actor.alternateId` - Whether one administrator drove the entire lifecycle

## Use Cases
- Reconstructing the lifecycle of a suspicious or short-lived application
- Determining who was provisioned into an application and when
- Investigating unauthorized SAML or integration authentication failures
- Scoping data exposure for an application involved in an incident
