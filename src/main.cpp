#define WIN32_LEAN_AND_MEAN
#define INITGUID
#include <windows.h>
#include <objbase.h>
#include <tdh.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <map>
#include <vector>
#include <string>
#include <set>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

// Session name for live capture
#define ETW_QUERY_SESSION_NAME L"EtwQueryLiveCapture"

// Structure to store captured event property info
struct CapturedProperty {
    std::wstring name;
    USHORT inType;
    USHORT outType;
    ULONG flags;
};

// Structure to store captured event info
struct CapturedEvent {
    std::wstring eventName;
    std::wstring taskName;
    std::wstring opcodeName;
    USHORT eventId;
    UCHAR version;
    ULONGLONG keywords;
    std::vector<CapturedProperty> properties;
    ULONG hitCount;
};

// Global state for live capture
struct LiveCaptureState {
    std::map<ULONGLONG, CapturedEvent> uniqueEvents;  // Key: eventId << 32 | version << 24 | opcode
    ULONG totalEvents;
    GUID providerGuid;
    bool captureActive;
    DWORD captureStartTime;
    DWORD captureDurationMs;
};

static LiveCaptureState g_captureState;

// Structure to track map references for later printing
struct MapReference {
    std::wstring mapName;
    EVENT_DESCRIPTOR eventDesc;  // Need an event that uses this map to query it
};

// Global collection of maps encountered during enumeration
static std::map<std::wstring, MapReference> g_collectedMaps;

// Convert TDH in-type to string
const wchar_t* GetInTypeString(USHORT inType)
{
    switch (inType)
    {
    case TDH_INTYPE_NULL: return L"NULL";
    case TDH_INTYPE_UNICODESTRING: return L"UNICODESTRING";
    case TDH_INTYPE_ANSISTRING: return L"ANSISTRING";
    case TDH_INTYPE_INT8: return L"INT8";
    case TDH_INTYPE_UINT8: return L"UINT8";
    case TDH_INTYPE_INT16: return L"INT16";
    case TDH_INTYPE_UINT16: return L"UINT16";
    case TDH_INTYPE_INT32: return L"INT32";
    case TDH_INTYPE_UINT32: return L"UINT32";
    case TDH_INTYPE_INT64: return L"INT64";
    case TDH_INTYPE_UINT64: return L"UINT64";
    case TDH_INTYPE_FLOAT: return L"FLOAT";
    case TDH_INTYPE_DOUBLE: return L"DOUBLE";
    case TDH_INTYPE_BOOLEAN: return L"BOOLEAN";
    case TDH_INTYPE_BINARY: return L"BINARY";
    case TDH_INTYPE_GUID: return L"GUID";
    case TDH_INTYPE_POINTER: return L"POINTER";
    case TDH_INTYPE_FILETIME: return L"FILETIME";
    case TDH_INTYPE_SYSTEMTIME: return L"SYSTEMTIME";
    case TDH_INTYPE_SID: return L"SID";
    case TDH_INTYPE_HEXINT32: return L"HEXINT32";
    case TDH_INTYPE_HEXINT64: return L"HEXINT64";
    case TDH_INTYPE_COUNTEDSTRING: return L"COUNTEDSTRING";
    case TDH_INTYPE_COUNTEDANSISTRING: return L"COUNTEDANSISTRING";
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING: return L"REVERSEDCOUNTEDSTRING";
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING: return L"REVERSEDCOUNTEDANSISTRING";
    case TDH_INTYPE_NONNULLTERMINATEDSTRING: return L"NONNULLTERMINATEDSTRING";
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING: return L"NONNULLTERMINATEDANSISTRING";
    case TDH_INTYPE_UNICODECHAR: return L"UNICODECHAR";
    case TDH_INTYPE_ANSICHAR: return L"ANSICHAR";
    case TDH_INTYPE_SIZET: return L"SIZET";
    case TDH_INTYPE_HEXDUMP: return L"HEXDUMP";
    case TDH_INTYPE_WBEMSID: return L"WBEMSID";
    default: return L"UNKNOWN";
    }
}

// Convert TDH out-type to string
const wchar_t* GetOutTypeString(USHORT outType)
{
    switch (outType)
    {
    case TDH_OUTTYPE_NULL: return L"NULL";
    case TDH_OUTTYPE_STRING: return L"STRING";
    case TDH_OUTTYPE_DATETIME: return L"DATETIME";
    case TDH_OUTTYPE_BYTE: return L"BYTE";
    case TDH_OUTTYPE_UNSIGNEDBYTE: return L"UNSIGNEDBYTE";
    case TDH_OUTTYPE_SHORT: return L"SHORT";
    case TDH_OUTTYPE_UNSIGNEDSHORT: return L"UNSIGNEDSHORT";
    case TDH_OUTTYPE_INT: return L"INT";
    case TDH_OUTTYPE_UNSIGNEDINT: return L"UNSIGNEDINT";
    case TDH_OUTTYPE_LONG: return L"LONG";
    case TDH_OUTTYPE_UNSIGNEDLONG: return L"UNSIGNEDLONG";
    case TDH_OUTTYPE_FLOAT: return L"FLOAT";
    case TDH_OUTTYPE_DOUBLE: return L"DOUBLE";
    case TDH_OUTTYPE_BOOLEAN: return L"BOOLEAN";
    case TDH_OUTTYPE_GUID: return L"GUID";
    case TDH_OUTTYPE_HEXBINARY: return L"HEXBINARY";
    case TDH_OUTTYPE_HEXINT8: return L"HEXINT8";
    case TDH_OUTTYPE_HEXINT16: return L"HEXINT16";
    case TDH_OUTTYPE_HEXINT32: return L"HEXINT32";
    case TDH_OUTTYPE_HEXINT64: return L"HEXINT64";
    case TDH_OUTTYPE_PID: return L"PID";
    case TDH_OUTTYPE_TID: return L"TID";
    case TDH_OUTTYPE_PORT: return L"PORT";
    case TDH_OUTTYPE_IPV4: return L"IPV4";
    case TDH_OUTTYPE_IPV6: return L"IPV6";
    case TDH_OUTTYPE_SOCKETADDRESS: return L"SOCKETADDRESS";
    case TDH_OUTTYPE_CIMDATETIME: return L"CIMDATETIME";
    case TDH_OUTTYPE_ETWTIME: return L"ETWTIME";
    case TDH_OUTTYPE_XML: return L"XML";
    case TDH_OUTTYPE_ERRORCODE: return L"ERRORCODE";
    case TDH_OUTTYPE_WIN32ERROR: return L"WIN32ERROR";
    case TDH_OUTTYPE_NTSTATUS: return L"NTSTATUS";
    case TDH_OUTTYPE_HRESULT: return L"HRESULT";
    case TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME: return L"CULTURE_INSENSITIVE_DATETIME";
    case TDH_OUTTYPE_JSON: return L"JSON";
    case TDH_OUTTYPE_REDUCEDSTRING: return L"REDUCEDSTRING";
    case TDH_OUTTYPE_NOPRINT: return L"NOPRINT";
    default: return L"UNKNOWN";
    }
}

// Case-insensitive substring search
bool ContainsSubstringIgnoreCase(const wchar_t* str, const wchar_t* substr)
{
    if (!str || !substr) return false;

    size_t strLen = wcslen(str);
    size_t substrLen = wcslen(substr);

    if (substrLen > strLen) return false;

    for (size_t i = 0; i <= strLen - substrLen; i++)
    {
        if (_wcsnicmp(str + i, substr, substrLen) == 0)
            return true;
    }
    return false;
}

void PrintUsage(const wchar_t* programName)
{
    wprintf(L"Usage: %ls <ProviderName> [EventFilter] [-properties]\n", programName);
    wprintf(L"\n");
    wprintf(L"  ProviderName  - Name of the ETW provider (e.g., Microsoft-Windows-Kernel-Process)\n");
    wprintf(L"  EventFilter   - Optional: Substring filter for event names (case insensitive)\n");
    wprintf(L"                  Matches events containing the filter text\n");
    wprintf(L"  -properties   - Show detailed property information for each event\n");
    wprintf(L"\n");
    wprintf(L"For manifest-based providers, events are enumerated from the registered schema.\n");
    wprintf(L"For TraceLogging providers, a 20-second live capture is performed automatically\n");
    wprintf(L"(requires Administrator privileges).\n");
    wprintf(L"\n");
    wprintf(L"Examples:\n");
    wprintf(L"  %ls Microsoft-Windows-Kernel-Process\n", programName);
    wprintf(L"  %ls Microsoft-Windows-Kernel-Process Process\n", programName);
    wprintf(L"  %ls Microsoft-Windows-Kernel-Process Start -properties\n", programName);
}

// Get provider GUID from provider name
ULONG GetProviderGuid(const wchar_t* providerName, GUID* providerGuid)
{
    ULONG status = ERROR_SUCCESS;
    PROVIDER_ENUMERATION_INFO* penum = NULL;
    ULONG bufferSize = 0;

    // First call to get required buffer size
    status = TdhEnumerateProviders(penum, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        penum = (PROVIDER_ENUMERATION_INFO*)malloc(bufferSize);
        if (penum == NULL)
        {
            return ERROR_OUTOFMEMORY;
        }

        status = TdhEnumerateProviders(penum, &bufferSize);
    }

    if (status != ERROR_SUCCESS)
    {
        free(penum);
        return status;
    }

    // Search for the provider by name
    bool found = false;
    for (ULONG i = 0; i < penum->NumberOfProviders; i++)
    {
        TRACE_PROVIDER_INFO* pinfo = &penum->TraceProviderInfoArray[i];
        const wchar_t* name = (const wchar_t*)((BYTE*)penum + pinfo->ProviderNameOffset);

        if (_wcsicmp(name, providerName) == 0)
        {
            *providerGuid = pinfo->ProviderGuid;
            found = true;
            break;
        }
    }

    free(penum);

    if (!found)
    {
        return ERROR_NOT_FOUND;
    }

    return ERROR_SUCCESS;
}

// Helper to get a valid string from an offset, returns NULL if invalid/empty
const wchar_t* GetStringFromOffset(TRACE_EVENT_INFO* eventInfo, ULONG offset)
{
    if (offset == 0)
        return NULL;

    const wchar_t* str = (const wchar_t*)((BYTE*)eventInfo + offset);
    if (str[0] == L'\0')
        return NULL;

    return str;
}

// Get the best available event name
const wchar_t* GetEventDisplayName(TRACE_EVENT_INFO* eventInfo, wchar_t* fallbackBuffer, size_t fallbackSize)
{
    // Try event name first
    const wchar_t* name = GetStringFromOffset(eventInfo, eventInfo->EventNameOffset);
    if (name)
        return name;

    // Try task name + opcode name
    const wchar_t* taskName = GetStringFromOffset(eventInfo, eventInfo->TaskNameOffset);
    const wchar_t* opcodeName = GetStringFromOffset(eventInfo, eventInfo->OpcodeNameOffset);

    if (taskName && opcodeName)
    {
        swprintf_s(fallbackBuffer, fallbackSize, L"%ls/%ls", taskName, opcodeName);
        return fallbackBuffer;
    }

    if (taskName)
        return taskName;

    if (opcodeName)
        return opcodeName;

    // Last resort: use Event ID
    swprintf_s(fallbackBuffer, fallbackSize, L"EventId_%u_v%u",
        eventInfo->EventDescriptor.Id,
        eventInfo->EventDescriptor.Version);
    return fallbackBuffer;
}

// Check if event matches filter (substring, case insensitive)
bool EventMatchesFilter(TRACE_EVENT_INFO* eventInfo, const wchar_t* filterEventName, wchar_t* nameFallback, size_t fallbackSize)
{
    if (filterEventName == NULL)
        return true;

    const wchar_t* eventName = GetEventDisplayName(eventInfo, nameFallback, fallbackSize);
    const wchar_t* taskName = GetStringFromOffset(eventInfo, eventInfo->TaskNameOffset);
    const wchar_t* opcodeName = GetStringFromOffset(eventInfo, eventInfo->OpcodeNameOffset);

    if (ContainsSubstringIgnoreCase(eventName, filterEventName))
        return true;
    if (ContainsSubstringIgnoreCase(taskName, filterEventName))
        return true;
    if (ContainsSubstringIgnoreCase(opcodeName, filterEventName))
        return true;

    return false;
}

// Print all collected maps and their values
void PrintCollectedMaps(const GUID* providerGuid)
{
    if (g_collectedMaps.empty())
        return;

    wprintf(L"\n");
    wprintf(L"================================================================================\n");
    wprintf(L"Map Definitions\n");
    wprintf(L"================================================================================\n");

    for (const auto& pair : g_collectedMaps)
    {
        const MapReference& mapRef = pair.second;

        wprintf(L"\n%ls:\n", mapRef.mapName.c_str());

        // Create a minimal EVENT_RECORD to query the map
        EVENT_RECORD eventRecord = {0};
        eventRecord.EventHeader.ProviderId = *providerGuid;
        eventRecord.EventHeader.EventDescriptor = mapRef.eventDesc;

        // Get buffer size for map info
        ULONG bufferSize = 0;
        ULONG status = TdhGetEventMapInformation(
            &eventRecord,
            (LPWSTR)mapRef.mapName.c_str(),
            NULL,
            &bufferSize);

        if (status != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"  (Unable to retrieve map info: error %u)\n", status);
            continue;
        }

        EVENT_MAP_INFO* mapInfo = (EVENT_MAP_INFO*)malloc(bufferSize);
        if (!mapInfo)
        {
            wprintf(L"  (Out of memory)\n");
            continue;
        }

        status = TdhGetEventMapInformation(
            &eventRecord,
            (LPWSTR)mapRef.mapName.c_str(),
            mapInfo,
            &bufferSize);

        if (status != ERROR_SUCCESS)
        {
            wprintf(L"  (Unable to retrieve map info: error %u)\n", status);
            free(mapInfo);
            continue;
        }

        // Determine map type
        const wchar_t* mapType = L"ValueMap";
        if (mapInfo->Flag == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP)
        {
            mapType = L"Bitmap (flags)";
        }
        else if (mapInfo->Flag == EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP)
        {
            mapType = L"PatternMap";
        }

        wprintf(L"  Type: %ls, %u entries\n", mapType, mapInfo->EntryCount);

        // Print each entry
        for (ULONG i = 0; i < mapInfo->EntryCount; i++)
        {
            EVENT_MAP_ENTRY* entry = &mapInfo->MapEntryArray[i];

            // Get the value name string
            const wchar_t* valueName = L"(unknown)";
            if (entry->OutputOffset > 0)
            {
                valueName = (const wchar_t*)((BYTE*)mapInfo + entry->OutputOffset);
            }

            // For bitmap entries, the value might be a flag (bit position)
            if (mapInfo->Flag == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP)
            {
                wprintf(L"    0x%08X = %ls\n", entry->Value, valueName);
            }
            else
            {
                wprintf(L"    %10u = %ls\n", entry->Value, valueName);
            }
        }

        free(mapInfo);
    }
}

// Print event in single-line format
void PrintEventLine(TRACE_EVENT_INFO* eventInfo, const wchar_t* filterEventName, bool showProperties, const EVENT_DESCRIPTOR* eventDesc)
{
    wchar_t nameFallback[256];

    if (!EventMatchesFilter(eventInfo, filterEventName, nameFallback, _countof(nameFallback)))
        return;

    const wchar_t* eventName = GetEventDisplayName(eventInfo, nameFallback, _countof(nameFallback));
    const wchar_t* taskName = GetStringFromOffset(eventInfo, eventInfo->TaskNameOffset);
    const wchar_t* opcodeName = GetStringFromOffset(eventInfo, eventInfo->OpcodeNameOffset);

    // Build task/opcode suffix if different from event name
    wchar_t suffix[128] = L"";
    if (taskName && opcodeName && wcscmp(eventName, taskName) != 0)
    {
        swprintf_s(suffix, _countof(suffix), L" [%ls/%ls]", taskName, opcodeName);
    }
    else if (taskName && wcscmp(eventName, taskName) != 0)
    {
        swprintf_s(suffix, _countof(suffix), L" [%ls]", taskName);
    }

    // Single line: EventName (ID:X v:Y) Keywords:0xNNN [Task/Opcode] (N properties)
    wprintf(L"%-40ls  ID:%-4u v:%-2u  Keywords:0x%016llX%ls  (%u props)\n",
        eventName,
        eventInfo->EventDescriptor.Id,
        eventInfo->EventDescriptor.Version,
        eventInfo->EventDescriptor.Keyword,
        suffix,
        eventInfo->TopLevelPropertyCount);

    if (showProperties && eventInfo->TopLevelPropertyCount > 0)
    {
        for (ULONG i = 0; i < eventInfo->TopLevelPropertyCount; i++)
        {
            EVENT_PROPERTY_INFO* propInfo = &eventInfo->EventPropertyInfoArray[i];
            const wchar_t* propName = (const wchar_t*)((BYTE*)eventInfo + propInfo->NameOffset);

            // Build additional info string
            wchar_t extra[128] = L"";
            if (propInfo->Flags & PropertyStruct)
            {
                swprintf_s(extra, _countof(extra), L" struct[%u members]", propInfo->structType.NumOfStructMembers);
            }
            else if (propInfo->nonStructType.MapNameOffset > 0)
            {
                const wchar_t* mapName = (const wchar_t*)((BYTE*)eventInfo + propInfo->nonStructType.MapNameOffset);
                swprintf_s(extra, _countof(extra), L" map:%ls", mapName);

                // Collect map reference for later printing
                if (eventDesc != NULL && g_collectedMaps.find(mapName) == g_collectedMaps.end())
                {
                    MapReference mapRef;
                    mapRef.mapName = mapName;
                    mapRef.eventDesc = *eventDesc;
                    g_collectedMaps[mapName] = mapRef;
                }
            }

            // Single line per property: indented name, InType -> OutType, extras
            wprintf(L"    %-30ls  %ls -> %ls%ls\n",
                propName,
                GetInTypeString(propInfo->nonStructType.InType),
                GetOutTypeString(propInfo->nonStructType.OutType),
                extra);
        }
    }
}

// Generate unique key for an event
ULONGLONG MakeEventKey(USHORT eventId, UCHAR version, UCHAR opcode)
{
    return ((ULONGLONG)eventId << 32) | ((ULONGLONG)version << 24) | (ULONGLONG)opcode;
}

// ETW event callback for live capture
void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord)
{
    if (!g_captureState.captureActive)
        return;

    // Check if capture time has elapsed
    if (GetTickCount() - g_captureState.captureStartTime >= g_captureState.captureDurationMs)
    {
        g_captureState.captureActive = false;
        return;
    }

    // Only process events from our target provider
    if (!IsEqualGUID(eventRecord->EventHeader.ProviderId, g_captureState.providerGuid))
        return;

    g_captureState.totalEvents++;

    // Create event key
    ULONGLONG eventKey = MakeEventKey(
        eventRecord->EventHeader.EventDescriptor.Id,
        eventRecord->EventHeader.EventDescriptor.Version,
        eventRecord->EventHeader.EventDescriptor.Opcode);

    // Check if we've already seen this event type
    auto it = g_captureState.uniqueEvents.find(eventKey);
    if (it != g_captureState.uniqueEvents.end())
    {
        it->second.hitCount++;
        return;
    }

    // New event type - get its schema using TdhGetEventInformation
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(eventRecord, 0, NULL, NULL, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER)
        return;

    TRACE_EVENT_INFO* eventInfo = (TRACE_EVENT_INFO*)malloc(bufferSize);
    if (!eventInfo)
        return;

    status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status != ERROR_SUCCESS)
    {
        free(eventInfo);
        return;
    }

    // Extract event information
    CapturedEvent captured;
    captured.eventId = eventRecord->EventHeader.EventDescriptor.Id;
    captured.version = eventRecord->EventHeader.EventDescriptor.Version;
    captured.keywords = eventRecord->EventHeader.EventDescriptor.Keyword;
    captured.hitCount = 1;

    // Get event name
    wchar_t nameFallback[256];
    const wchar_t* eventName = GetEventDisplayName(eventInfo, nameFallback, _countof(nameFallback));
    captured.eventName = eventName;

    // Get task and opcode names
    const wchar_t* taskName = GetStringFromOffset(eventInfo, eventInfo->TaskNameOffset);
    const wchar_t* opcodeName = GetStringFromOffset(eventInfo, eventInfo->OpcodeNameOffset);
    if (taskName) captured.taskName = taskName;
    if (opcodeName) captured.opcodeName = opcodeName;

    // Extract properties
    for (ULONG i = 0; i < eventInfo->TopLevelPropertyCount; i++)
    {
        EVENT_PROPERTY_INFO* propInfo = &eventInfo->EventPropertyInfoArray[i];
        const wchar_t* propName = (const wchar_t*)((BYTE*)eventInfo + propInfo->NameOffset);

        CapturedProperty prop;
        prop.name = propName;
        prop.inType = propInfo->nonStructType.InType;
        prop.outType = propInfo->nonStructType.OutType;
        prop.flags = propInfo->Flags;

        captured.properties.push_back(prop);
    }

    g_captureState.uniqueEvents[eventKey] = captured;

    free(eventInfo);

    // Print progress dot every 10 unique events
    if (g_captureState.uniqueEvents.size() % 10 == 0)
    {
        wprintf(L".");
    }
}

// Buffer callback (required but not used for real-time)
ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW /*logFile*/)
{
    // Return TRUE to continue processing, FALSE to stop
    return g_captureState.captureActive ? TRUE : FALSE;
}

// Print captured events summary
void PrintCapturedEvents(const wchar_t* filterEventName, bool showProperties)
{
    wprintf(L"\n\nCapture complete!\n");
    wprintf(L"Total events received: %u\n", g_captureState.totalEvents);
    wprintf(L"Unique event types discovered: %zu\n\n", g_captureState.uniqueEvents.size());

    if (g_captureState.uniqueEvents.empty())
    {
        wprintf(L"No events were captured. The provider may not be actively generating events.\n");
        wprintf(L"Try running an application that uses this provider and capture again.\n");
        return;
    }

    ULONG matchCount = 0;

    for (const auto& pair : g_captureState.uniqueEvents)
    {
        const CapturedEvent& evt = pair.second;

        // Apply filter if specified
        if (filterEventName != NULL)
        {
            bool matches = ContainsSubstringIgnoreCase(evt.eventName.c_str(), filterEventName) ||
                          ContainsSubstringIgnoreCase(evt.taskName.c_str(), filterEventName) ||
                          ContainsSubstringIgnoreCase(evt.opcodeName.c_str(), filterEventName);
            if (!matches)
                continue;
        }

        matchCount++;

        // Build task/opcode suffix if different from event name
        wchar_t suffix[128] = L"";
        if (!evt.taskName.empty() && !evt.opcodeName.empty() && evt.eventName != evt.taskName)
        {
            swprintf_s(suffix, _countof(suffix), L" [%ls/%ls]", evt.taskName.c_str(), evt.opcodeName.c_str());
        }
        else if (!evt.taskName.empty() && evt.eventName != evt.taskName)
        {
            swprintf_s(suffix, _countof(suffix), L" [%ls]", evt.taskName.c_str());
        }

        wprintf(L"%-40ls  ID:%-4u v:%-2u  Keywords:0x%016llX%ls  (%zu props)  [%u hits]\n",
            evt.eventName.c_str(),
            evt.eventId,
            evt.version,
            evt.keywords,
            suffix,
            evt.properties.size(),
            evt.hitCount);

        if (showProperties && !evt.properties.empty())
        {
            for (const auto& prop : evt.properties)
            {
                wchar_t extra[64] = L"";
                if (prop.flags & PropertyStruct)
                {
                    wcscpy_s(extra, L" (struct)");
                }

                wprintf(L"    %-30ls  %ls -> %ls%ls\n",
                    prop.name.c_str(),
                    GetInTypeString(prop.inType),
                    GetOutTypeString(prop.outType),
                    extra);
            }
        }
    }

    if (filterEventName != NULL)
    {
        if (matchCount == 0)
        {
            wprintf(L"No captured events matching '%ls'.\n", filterEventName);
        }
        else
        {
            wprintf(L"\n%u events matched filter '%ls'\n", matchCount, filterEventName);
        }
    }
}

// Live capture events from a TraceLogging provider
ULONG CaptureProviderEvents(const GUID* providerGuid, const wchar_t* filterEventName, bool showProperties, DWORD durationSeconds)
{
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE sessionHandle = 0;
    TRACEHANDLE traceHandle = INVALID_PROCESSTRACE_HANDLE;

    // Calculate buffer size for EVENT_TRACE_PROPERTIES
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETW_QUERY_SESSION_NAME) + sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES* sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!sessionProperties)
        return ERROR_OUTOFMEMORY;

    ZeroMemory(sessionProperties, bufferSize);
    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Try to stop any existing session with this name
    ControlTraceW(0, ETW_QUERY_SESSION_NAME, sessionProperties, EVENT_TRACE_CONTROL_STOP);

    // Reset properties for new session
    ZeroMemory(sessionProperties, bufferSize);
    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1;
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wprintf(L"Starting live capture for %u seconds...\n", durationSeconds);
    wprintf(L"(Run applications that trigger events from this provider)\n\n");

    // Start trace session
    status = StartTraceW(&sessionHandle, ETW_QUERY_SESSION_NAME, sessionProperties);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"Failed to start trace session: %u\n", status);
        if (status == ERROR_ACCESS_DENIED)
        {
            wprintf(L"Administrator privileges are required for live ETW capture.\n");
        }
        free(sessionProperties);
        return status;
    }

    // Enable the provider on our session
    status = EnableTraceEx2(
        sessionHandle,
        providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,  // All keywords
        0,
        0,
        NULL);

    if (status != ERROR_SUCCESS)
    {
        wprintf(L"Failed to enable provider: %u\n", status);
        ControlTraceW(sessionHandle, NULL, sessionProperties, EVENT_TRACE_CONTROL_STOP);
        free(sessionProperties);
        return status;
    }

    // Initialize capture state
    g_captureState.uniqueEvents.clear();
    g_captureState.totalEvents = 0;
    g_captureState.providerGuid = *providerGuid;
    g_captureState.captureActive = true;
    g_captureState.captureStartTime = GetTickCount();
    g_captureState.captureDurationMs = durationSeconds * 1000;

    // Open trace for real-time processing
    EVENT_TRACE_LOGFILEW logFile = {0};
    logFile.LoggerName = (LPWSTR)ETW_QUERY_SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;

    traceHandle = OpenTraceW(&logFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        status = GetLastError();
        wprintf(L"Failed to open trace: %u\n", status);
        ControlTraceW(sessionHandle, NULL, sessionProperties, EVENT_TRACE_CONTROL_STOP);
        free(sessionProperties);
        return status;
    }

    wprintf(L"Capturing");

    // Process events (this blocks until capture is complete or BufferCallback returns FALSE)
    status = ProcessTrace(&traceHandle, 1, NULL, NULL);

    // Clean up
    CloseTrace(traceHandle);

    // Disable provider and stop session
    EnableTraceEx2(sessionHandle, providerGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, NULL);
    ControlTraceW(sessionHandle, NULL, sessionProperties, EVENT_TRACE_CONTROL_STOP);
    free(sessionProperties);

    // Print results
    PrintCapturedEvents(filterEventName, showProperties);

    return ERROR_SUCCESS;
}

// Enumerate and print events for a provider
ULONG EnumerateProviderEvents(const GUID* providerGuid, const wchar_t* filterEventName, bool showProperties)
{
    ULONG status = ERROR_SUCCESS;
    PROVIDER_EVENT_INFO* eventInfoBuffer = NULL;
    ULONG bufferSize = 0;

    // Clear any previously collected maps
    g_collectedMaps.clear();

    // First call to get required buffer size
    status = TdhEnumerateManifestProviderEvents((GUID*)providerGuid, eventInfoBuffer, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        eventInfoBuffer = (PROVIDER_EVENT_INFO*)malloc(bufferSize);
        if (eventInfoBuffer == NULL)
        {
            return ERROR_OUTOFMEMORY;
        }

        status = TdhEnumerateManifestProviderEvents((GUID*)providerGuid, eventInfoBuffer, &bufferSize);
    }

    if (status != ERROR_SUCCESS)
    {
        free(eventInfoBuffer);
        return status;
    }

    wprintf(L"Found %u events\n\n", eventInfoBuffer->NumberOfEvents);

    ULONG matchCount = 0;

    // Iterate through each event
    for (ULONG i = 0; i < eventInfoBuffer->NumberOfEvents; i++)
    {
        EVENT_DESCRIPTOR* eventDesc = &eventInfoBuffer->EventDescriptorsArray[i];

        // Get event information
        TRACE_EVENT_INFO* traceEventInfo = NULL;
        ULONG traceEventInfoSize = 0;

        status = TdhGetManifestEventInformation((GUID*)providerGuid, eventDesc, traceEventInfo, &traceEventInfoSize);
        if (status == ERROR_INSUFFICIENT_BUFFER)
        {
            traceEventInfo = (TRACE_EVENT_INFO*)malloc(traceEventInfoSize);
            if (traceEventInfo == NULL)
            {
                continue;
            }

            status = TdhGetManifestEventInformation((GUID*)providerGuid, eventDesc, traceEventInfo, &traceEventInfoSize);
        }

        if (status == ERROR_SUCCESS && traceEventInfo != NULL)
        {
            wchar_t nameFallback[256];
            if (EventMatchesFilter(traceEventInfo, filterEventName, nameFallback, _countof(nameFallback)))
            {
                matchCount++;
                PrintEventLine(traceEventInfo, filterEventName, showProperties, eventDesc);
            }
        }

        free(traceEventInfo);
    }

    free(eventInfoBuffer);

    if (filterEventName != NULL && matchCount == 0)
    {
        wprintf(L"No events matching '%ls' found in this provider.\n", filterEventName);
        return ERROR_NOT_FOUND;
    }

    if (filterEventName != NULL)
    {
        wprintf(L"\n%u events matched filter '%ls'\n", matchCount, filterEventName);
    }

    // Print collected maps if showing properties
    if (showProperties)
    {
        PrintCollectedMaps(providerGuid);
    }

    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    const wchar_t* providerName = argv[1];
    const wchar_t* eventFilter = NULL;
    bool showProperties = false;

    // Parse arguments
    for (int i = 2; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"-properties") == 0)
        {
            showProperties = true;
        }
        else if (eventFilter == NULL)
        {
            eventFilter = argv[i];
        }
    }

    wprintf(L"ETW Event Query\n");
    wprintf(L"===============\n\n");

    // Get provider GUID from name
    GUID providerGuid = {0};
    ULONG status = GetProviderGuid(providerName, &providerGuid);

    if (status == ERROR_NOT_FOUND)
    {
        wprintf(L"Error: Provider '%ls' not found.\n", providerName);
        wprintf(L"\nMake sure the provider name is correct. You can use:\n");
        wprintf(L"  logman query providers\n");
        wprintf(L"to list available ETW providers.\n");
        return 1;
    }
    else if (status != ERROR_SUCCESS)
    {
        wprintf(L"Error enumerating providers: %u\n", status);
        return 1;
    }

    wchar_t guidStr[40];
    StringFromGUID2(providerGuid, guidStr, 40);
    wprintf(L"Provider: %ls\n", providerName);
    wprintf(L"GUID: %ls\n", guidStr);

    if (eventFilter)
    {
        wprintf(L"Filter: %ls\n", eventFilter);
    }

    wprintf(L"\n");

    // Enumerate events
    status = EnumerateProviderEvents(&providerGuid, eventFilter, showProperties);

    if (status != ERROR_SUCCESS && status != ERROR_NOT_FOUND)
    {
        // Check if this is a non-manifest provider (TraceLogging/MOF)
        if (status == ERROR_EMPTY || status == ERROR_INVALID_DATA)
        {
            wprintf(L"No manifest events found for this provider.\n");
            wprintf(L"This provider likely uses TraceLogging - attempting live capture...\n\n");

            // Perform live capture for 20 seconds
            status = CaptureProviderEvents(&providerGuid, eventFilter, showProperties, 20);
            if (status != ERROR_SUCCESS)
            {
                return 1;
            }
            return 0;
        }
        else
        {
            wprintf(L"\nError enumerating events: %u\n", status);
            return 1;
        }
    }

    return 0;
}
