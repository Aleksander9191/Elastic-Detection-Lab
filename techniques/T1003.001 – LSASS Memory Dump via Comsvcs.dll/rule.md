```kql
winlog.event_data.OriginalFileName:"RUNDLL32.EXE"
and
winlog.event_data.CommandLine:*comsvcs.dll*
and
winlog.event_data.CommandLine:*MiniDump*
```
