```kql
event.code:"13"
and winlog.event_data.TargetObject:*CurrentVersion*
and winlog.event_data.TargetObject:*Run*
and winlog.event_data.Image:*\\reg.exe
```
