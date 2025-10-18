
```
dataset = xdr_data 
| filter dns_resolutions != null 
| fields agent_id, agent_hostname, agent_ip_addresses, actor_process_image_name, actor_process_instance_id, dns_query_name 
| comp values(dns_query_name) as dns_query_names by agent_id, agent_hostname, agent_ip_addresses, actor_process_image_name, actor_process_instance_id
```