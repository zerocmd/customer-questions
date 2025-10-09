dataset = xdr_data
| filter event_sub_type = FILE_CREATE_NEW and action_file_path contains "User Data\Default\Extensions"
| alter extension_id = arrayindex(regextract(action_file_path,"\\Extensions\\(.*)\\[0-9]"),0)
| alter action_file_path = arrayindex(regextract(action_file_path,"(.*)\\[0-9]"),0)
| fields agent_hostname, _time, extension_id, action_file_path