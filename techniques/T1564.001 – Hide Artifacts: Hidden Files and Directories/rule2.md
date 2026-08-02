```kql
event.code:"1"
and winlog.event_data.OriginalFileName:"ATTRIB.EXE"
and (
    winlog.event_data.CommandLine:*+h*
    or
    winlog.event_data.CommandLine:*+s*
)
```
