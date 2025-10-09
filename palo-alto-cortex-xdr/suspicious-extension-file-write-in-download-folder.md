config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE and event_sub_type = ENUM.FILE_WRITE and action_file_path contains "Downloads"
| filter action_file_sha256 != null
| filter action_file_extension in ("exe", "dll", "ps1", "vbs", "js")
| fields _time, agent_hostname, action_file_name, action_file_path, action_file_sha256