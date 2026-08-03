```kql
event.code:"13"
and winlog.event_data.TargetObject:*Winlogon*
and winlog.event_data.TargetObject:*Shell*
```
