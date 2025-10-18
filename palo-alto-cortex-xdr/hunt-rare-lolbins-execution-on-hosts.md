```
config case_sensitive = falseconfig case_sensitive = false
| preset = xdr_process 
| filter action_process_image_name in (
    "wmic.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "mshta.exe", 
    "cscript.exe", "wscript.exe","forfiles.exe", "at.exe", "net.exe", "netsh.exe", 
    "whoami.exe", "nltest.exe", "dsquery.exe", "ldifde.exe", "csvde.exe"
)
| comp count() as count by agent_hostname, action_process_image_name
```