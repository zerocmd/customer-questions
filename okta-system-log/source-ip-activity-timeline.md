# Full Source IP Activity Timeline

## Description
Returns every Okta System Log event originating from a single source IP, across all event types. This gives the blast radius of an address rather than just its authentication history.

## Query Type
Investigation (with variable)

## Variables
- `IP_ADDRESS` - Source IP address to investigate (e.g., "203.0.113.24")

## Okta System Log Filter
```
client.ipAddress eq "IP_ADDRESS"
```

## Detection Logic
- No `eventType` constraint, so admin actions, application changes, and provisioning from the address are returned alongside sign-ins
- Every identity that acted from the address appears in `actor.alternateId`

## Output Fields
- `actor.alternateId` - Each distinct value is another account reached from the address; the count is the blast radius
- `eventType` - Administrative and provisioning types are what an authentication-only view would miss
- `securityContext.asOrg` / `securityContext.isp` - Settles whether the address is corporate egress, a VPN, or genuinely foreign infrastructure
- `target.alternateId` / `target.displayName` - What each action affected
- `displayMessage` - Human-readable summary across a mixed-type result set

## Use Cases
- Blast radius for an IP indicator from threat intelligence or an EDR alert
- Finding administrative changes made from an address after a successful sign-in
- Identifying every account reached from attacker infrastructure
- Distinguishing a corporate egress from genuinely anomalous infrastructure
