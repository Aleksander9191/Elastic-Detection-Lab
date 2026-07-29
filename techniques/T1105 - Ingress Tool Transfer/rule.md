
```kql
event.code:1 and
(
(
winlog.event_data.OriginalFileName:"CertUtil.exe"
and
(
winlog.event_data.CommandLine:*http* or
winlog.event_data.CommandLine:*https*
)
)
or
(
winlog.event_data.OriginalFileName:"curl.exe"
and
(
winlog.event_data.CommandLine:*http* or
winlog.event_data.CommandLine:*https*
)
)
)
```
