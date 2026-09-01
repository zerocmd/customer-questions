# Privilege Changes Affecting an Account

## Description
Returns the role grants, group membership changes, and application assignments where a specific user is the target — access granted to or removed from an account, which is a different question from what the account did itself.

## Query Type
Investigation (with variable)

## Variables
- `OKTA_USER_LOGIN` - Okta user login whose access changes are under investigation (e.g., "jsmith@contoso.com")

## Okta System Log Filter
```
(eventType sw "user.account.privilege" or eventType sw "group.privilege" or eventType sw "group.user_membership" or eventType sw "application.user_membership") and target.alternateId eq "OKTA_USER_LOGIN"
```

## Detection Logic
- `sw` (starts with) matches each family in both directions, so revokes and removals are returned alongside grants and additions
- `user.account.privilege.grant` is an administrator role granted directly to the user
- Scoped by `target.alternateId`, so results are changes made *to* the account rather than *by* it
- Group privilege events name the **group** as the target rather than the user, so they appear here only where the user is also recorded as a target
- A user added to an already-privileged group produces no privilege event of its own; the membership event is the only record

## Output Fields
- `actor.alternateId` - Who made the change; a mismatch with the target, outside a change window, is the finding
- `eventType` - Identifies which access route was used and in which direction, which determines where to look next
- `target.type` - `target` is an array here, so this is what separates the User entry from the UserGroup or AppInstance entry in the same event
- `target.displayName` - The role, group, or application involved
- `debugContext.debugData.privilegeGranted` - Role conveyed on a privilege grant

## Use Cases
- Privilege escalation investigation scoped to one account
- Determining what an account could reach after a suspected compromise
- Access review and entitlement audit for a specific user
- Detecting access granted through group membership rather than direct assignment
