```kql
event.code:"1"
and winlog.event_data.Image:*\\powershell.exe
and winlog.event_data.CommandLine:*Set-ItemProperty*
and winlog.event_data.CommandLine:*CurrentVersion\\Run*
```
