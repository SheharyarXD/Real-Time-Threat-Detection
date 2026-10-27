@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Sentinel - Backend Setup and API
pushd "%~dp0backend"
if errorlevel 1 goto failed
where py.exe >nul 2>&1
if not errorlevel 1 (
  py -3.12 --version >nul 2>&1
  if not errorlevel 1 goto python_launcher
)
where python.exe >nul 2>&1
if not errorlevel 1 (
  python -c "import sys;sys.exit(0 if sys.version_info >= (3,12) else 1)" >nul 2>&1
  if not errorlevel 1 goto python_command
)
echo Python 3.12 or later is required. Install it from https://www.python.org/downloads/
echo Or use: winget install --id Python.Python.3.12 --exact --source winget
goto failed
:python_launcher
py -3.12 run.py %*
goto finished
:python_command
python run.py %*
:finished
set "SENTINEL_BACKEND_EXIT=%ERRORLEVEL%"
if "%SENTINEL_BACKEND_EXIT%"=="0" goto success
:failed
echo Backend startup failed. Read backend\README.md and the error above.
pause
popd
exit /b 1
:success
popd
exit /b 0
