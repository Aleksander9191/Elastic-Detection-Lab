```kql
event.code:"1"
and winlog.event_data.Image:*powershell.exe
and winlog.event_data.CommandLine:*char*
and winlog.event_data.CommandLine:*join*
and (
    winlog.event_data.CommandLine:*$ps*
    or
    winlog.event_data.CommandLine:*$cmd*
)
```
