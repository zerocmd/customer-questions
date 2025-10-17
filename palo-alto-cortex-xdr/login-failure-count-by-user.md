```
preset = xdr_login_events
| filter outcome_reason != null and dst_user != null
| comp count() as failure_count by agent_hostname, dst_user, type, outcome_reason
| sort desc failure_count
```