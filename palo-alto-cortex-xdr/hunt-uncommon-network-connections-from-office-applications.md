```
config case_sensitive = false
| preset = network_story
| filter actor_process_image_name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe")
| filter action_remote_ip != null and dst_action_external_hostname != null
| filter not incidr(action_remote_ip, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
| comp count() as connection_count by agent_hostname, actor_process_image_name, action_remote_ip, dst_action_external_hostname, dst_action_country
| sort desc connection_count
```
