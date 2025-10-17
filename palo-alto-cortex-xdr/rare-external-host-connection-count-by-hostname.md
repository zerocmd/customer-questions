```
config case_sensitive = false
| preset = network_story
| filter agent_hostname = "workstation"
| filter dst_action_external_hostname = null and not is_known_private_ipv4(action_remote_ip)
| comp count() as connection_count by dst_action_country, action_remote_ip, action_remote_port
| filter connection_count < 100
| sort desc connection_count
```
