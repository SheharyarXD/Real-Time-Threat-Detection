@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0scripts\Install-Development.ps1"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
