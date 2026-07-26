
```kql
event.code:1 and (
  winlog.event_data.OriginalFileName:"net.exe" or
  winlog.event_data.OriginalFileName:"net1.exe" or
  winlog.event_data.OriginalFileName:"cmdkey.exe"
)
```
