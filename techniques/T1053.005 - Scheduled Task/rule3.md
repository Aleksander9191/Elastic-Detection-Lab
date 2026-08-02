```kql
event.code:"1"
and winlog.event_data.Image:*schtasks.exe
and winlog.event_data.CommandLine:*Create*
and winlog.event_data.CommandLine:*powershell.exe*
and winlog.event_data.CommandLine:*FromBase64String*
and winlog.event_data.CommandLine:*Get-ItemProperty*
```
