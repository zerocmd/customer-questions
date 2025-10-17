```
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name contains "powershell"
| filter actor_process_command_line ~= ".*-e[ncodedcommand]*\s+[A-Za-z0-9+/=]{50,}.*"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, action_process_username
| sort desc _time
```
