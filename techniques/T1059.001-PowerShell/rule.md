```kql
event.code:1 and
winlog.event_data.OriginalFileName:"PowerShell.EXE" and
(
  winlog.event_data.CommandLine:*-e* or
  winlog.event_data.CommandLine:*-enc* or
  winlog.event_data.CommandLine:*-encodedcommand*
)
```
