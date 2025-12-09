# etw-query

Command-line utility for querying ETW (Event Tracing for Windows) provider event schemas.

## Usage

```
etw-query.exe <ProviderName> [EventFilter] [-properties]
```

### Arguments

- `ProviderName` - Name of the ETW provider (e.g., `Microsoft-Windows-Kernel-Process`)
- `EventFilter` - Optional substring filter for event names (case insensitive). Matches events containing the filter text.
- `-properties` - Show detailed property information for each event

### Examples

List all events for a provider:
```
etw-query.exe Microsoft-Windows-Kernel-Process
```

Filter events containing "Process" (case insensitive):
```
etw-query.exe Microsoft-Windows-Kernel-Process Process
```

Show properties for events matching "Start":
```
etw-query.exe Microsoft-Windows-Kernel-Process Start -properties
```

### Sample Output

Without `-properties`:
```
ProcessStart                              ID:1    v:3   Keywords:0x0000000000000010  (11 props)
ProcessStop                               ID:2    v:3   Keywords:0x0000000000000010  (5 props)
```

With `-properties`:
```
ProcessStart                              ID:1    v:3   Keywords:0x0000000000000010  (11 props)
    ProcessID                       UINT32 -> UNSIGNEDINT
    CreateTime                      FILETIME -> DATETIME
    ParentProcessID                 UINT32 -> UNSIGNEDINT
    ...
```

## Building

Requires Visual Studio 2022 with C++ workload.

```cmd
msbuild etw-query.sln /p:Configuration=Release /p:Platform=x64
```

Output: `bin\Release\etw-query.exe`
