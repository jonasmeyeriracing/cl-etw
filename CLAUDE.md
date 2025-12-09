# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

This is a Visual Studio 2022 (v143 toolset) C++ project targeting Windows x64.

**Build via MSBuild:**
```cmd
msbuild etw-query.sln /p:Configuration=Release /p:Platform=x64
msbuild etw-query.sln /p:Configuration=Debug /p:Platform=x64
```

**Build via Visual Studio:**
Open `etw-query.sln` in Visual Studio 2022 and build (Ctrl+Shift+B).

**Output locations:**
- Release: `bin\Release\etw-query.exe`
- Debug: `bin\Debug\etw-query.exe`

## Project Overview

etw-query is a command-line utility for querying ETW (Event Tracing for Windows) provider event schemas. It uses the TDH (Trace Data Helper) API to enumerate ETW providers and display event property information.

**Usage:**
```cmd
etw-query.exe <ProviderName> [EventName]
```

**Key functionality:**
- Resolves ETW provider names to GUIDs via `TdhEnumerateProviders`
- Enumerates manifest-based provider events via `TdhEnumerateManifestProviderEvents`
- Retrieves event metadata (properties, types, keywords) via `TdhGetManifestEventInformation`
- Displays property information including InType, OutType, length, count, and map references

## Architecture

Single-file implementation in `src/main.cpp`. Key functions:
- `GetProviderGuid()` - Resolves provider name to GUID
- `EnumerateProviderEvents()` - Lists all events for a provider
- `PrintEventProperties()` - Displays detailed property info for an event
- `GetInTypeString()`/`GetOutTypeString()` - Convert TDH type constants to readable strings

**Dependencies:**
- Windows SDK (tdh.lib, ole32.lib)
- Requires Windows 10+ for full TDH API support
