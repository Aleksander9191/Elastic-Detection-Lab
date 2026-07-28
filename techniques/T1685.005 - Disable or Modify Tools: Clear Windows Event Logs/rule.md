```kql
event.code:1 and
winlog.event_data.OriginalFileName:"wevtutil.exe" and
(
    winlog.event_data.CommandLine:*cl* or
    winlog.event_data.CommandLine:*clear-log*
)
```
