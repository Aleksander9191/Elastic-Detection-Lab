```kql
event.code:"13"
and winlog.event_data.TargetObject:*Policies*
and winlog.event_data.TargetObject:*Explorer*
and winlog.event_data.TargetObject:*Run*
```
