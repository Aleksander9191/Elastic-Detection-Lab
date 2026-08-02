```kql
event.code:"1"
and winlog.event_data.Image:*schtasks.exe
and winlog.event_data.CommandLine:*create*
```
