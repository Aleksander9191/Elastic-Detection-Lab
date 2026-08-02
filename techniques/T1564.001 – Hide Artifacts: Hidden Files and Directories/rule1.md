```kql
event.code:"1"
and winlog.event_data.OriginalFileName:"REG.EXE"
and winlog.event_data.CommandLine:*Explorer\\Advanced*
and (
    winlog.event_data.CommandLine:*ShowSuperHidden*
    or
    winlog.event_data.CommandLine:*Hidden*
)
and winlog.event_data.CommandLine:*/d*
and winlog.event_data.CommandLine:*0*
```
