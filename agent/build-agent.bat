@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>nul
if errorlevel 1 (
  where winget >nul 2>nul
  if errorlevel 1 (
    echo Install .NET 10 SDK from https://dotnet.microsoft.com/download/dotnet/10.0 then run again.
    pause
    exit /b 1
  )
  winget install --id Microsoft.DotNet.SDK.10 --exact --source winget --accept-package-agreements --accept-source-agreements
  if errorlevel 1 exit /b 1
  set "PATH=%ProgramFiles%\dotnet;%PATH%"
)
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0scripts\Build-Agent.ps1"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
