```kql
event.code:"13"
and winlog.event_data.TargetObject:*Policies\\Explorer\\Run*
and (
    winlog.event_data.Image:*powershell.exe
    or winlog.event_data.Image:*reg.exe
)
```
