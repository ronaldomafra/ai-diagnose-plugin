@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "_DIAGNOSE_MCP="
for /f "delims=" %%I in ('where $PATH:diagnose-mcp.exe 2^>nul') do if not defined _DIAGNOSE_MCP set "_DIAGNOSE_MCP=%%I"

if not defined _DIAGNOSE_MCP (
  1>&2 echo diagnose-mcp launcher: diagnose-mcp.exe was not found on PATH. Install it with "uv tool install PATH_TO_WHEEL" and restart Codex.
  exit /b 1
)

set "_PYTHON_OK="
set "_PYTHON_CHECKED="
for /f "delims=" %%I in ('where $PATH:py.exe 2^>nul') do if not defined _PYTHON_CHECKED (
  set "_PYTHON_CHECKED=1"
  "%%I" -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
  if not errorlevel 1 set "_PYTHON_OK=1"
)

if not defined _PYTHON_OK (
  set "_PYTHON_CHECKED="
  for /f "delims=" %%I in ('where $PATH:python.exe 2^>nul') do if not defined _PYTHON_CHECKED (
    set "_PYTHON_CHECKED=1"
    "%%I" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
    if not errorlevel 1 set "_PYTHON_OK=1"
  )
)

if not defined _PYTHON_OK (
  1>&2 echo diagnose-mcp launcher: Python 3.12 or newer is required. Install it, reinstall the diagnose wheel, and restart Codex.
  exit /b 1
)

rem Preserve DIAGNOSE_IPC_ENDPOINT and pass explicit --endpoint overrides unchanged.
rem The MCP process owns protocol errors, including TERMINAL_SERVER_OFFLINE.
"%_DIAGNOSE_MCP%" %*
exit /b %ERRORLEVEL%
