dataset = xdr_data 
| filter event_type = EVENT_LOG and action_evtlog_event_id = 4624
| fields action_evtlog_data_fields as event, agent_hostname, agent_ip_addresses
| alter domain_name = replace(json_extract(event, "$.TargetDomainName"), "\"","")
| filter domain_name = "AzureAD"
| alter username = replace(json_extract(event, "$.TargetUserName"), "\"","")
| filter username = "userprincipalname@contoso.com"
| comp count(UserName) as login_count by agent_hostname, username, domain_name