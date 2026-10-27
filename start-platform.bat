@echo off
setlocal EnableExtensions DisableDelayedExpansion
pushd "%~dp0"
if errorlevel 1 exit /b 1
echo Starting the backend setup in a separate window.
echo Complete PostgreSQL configuration and administrator setup there first.
start "Sentinel Backend" cmd.exe /d /k call "%~dp0start-backend.bat"
set "SENTINEL_API_URL=http://127.0.0.1:8000"
call "%~dp0start-dashboard.bat" --connected %*
set "SENTINEL_PLATFORM_EXIT=%ERRORLEVEL%"
popd
exit /b %SENTINEL_PLATFORM_EXIT%
