#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <tdh.h>
#include <evntrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ole32.lib")

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

// Print event in single-line format
void PrintEventLine(TRACE_EVENT_INFO* eventInfo, const wchar_t* filterEventName, bool showProperties)
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

// Enumerate and print events for a provider
ULONG EnumerateProviderEvents(const GUID* providerGuid, const wchar_t* filterEventName, bool showProperties)
{
    ULONG status = ERROR_SUCCESS;
    PROVIDER_EVENT_INFO* eventInfoBuffer = NULL;
    ULONG bufferSize = 0;

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
        if (status == ERROR_NOT_FOUND || status == ERROR_EMPTY)
        {
            wprintf(L"No manifest events found for this provider.\n");
            wprintf(L"This provider may use TraceLogging or MOF-based events instead.\n");
        }
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
                PrintEventLine(traceEventInfo, filterEventName, showProperties);
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
        wprintf(L"\nError enumerating events: %u\n", status);
        return 1;
    }

    return 0;
}
