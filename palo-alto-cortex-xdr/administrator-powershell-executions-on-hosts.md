config case_sensitive = false
| preset = xdr_process 
| filter agent_hostname = "workstation" and action_process_username contains "Administrator"
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name contains "powershell.exe"
| fields _time, agent_hostname, action_process_username, actor_process_command_line