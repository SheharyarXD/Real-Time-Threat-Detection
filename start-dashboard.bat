@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Sentinel SOC - Local Dashboard

pushd "%~dp0"
if errorlevel 1 goto folder_error

if not exist "package.json" goto incomplete_project
if not exist "scripts\start-dashboard.mjs" goto incomplete_project

echo.
echo ============================================================
echo   Sentinel SOC - Milestone 1 Dashboard
echo   Checks requirements, installs dependencies, and starts Next.js
echo ============================================================
echo.

call :check_node
if not errorlevel 1 goto node_ready

echo [SETUP] Node.js 22.13 or newer with npm is required.
where winget.exe >nul 2>&1
if errorlevel 1 goto manual_node

echo [SETUP] Installing Node.js LTS through Windows Package Manager.
echo [INFO] Windows may ask you to approve the installer or its terms.
winget.exe install --id OpenJS.NodeJS.LTS --exact --source winget
if errorlevel 1 goto node_install_error

rem Refresh the conventional Node installation paths in this window.
if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "PATH=%ProgramFiles(x86)%\nodejs;%PATH%"
if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
if exist "%ProgramFiles%\nodejs\node.exe" set "PATH=%ProgramFiles%\nodejs;%PATH%"
call :check_node
if errorlevel 1 goto restart_needed

:node_ready
node "scripts\start-dashboard.mjs" %*
set "SENTINEL_EXIT=%ERRORLEVEL%"
if "%SENTINEL_EXIT%"=="0" goto done
echo.
echo [ERROR] Setup or startup failed. Read the message above.
echo [TIP] Try start-dashboard.bat --reinstall if dependencies are damaged.
pause
:done
popd
exit /b %SENTINEL_EXIT%

:check_node
where node.exe >nul 2>&1
if errorlevel 1 exit /b 1
where npm.cmd >nul 2>&1
if errorlevel 1 exit /b 1
node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>22||(a===22&&b>=13)?0:1)" >nul 2>&1
exit /b %ERRORLEVEL%

:manual_node
echo [ACTION] Install Node.js LTS from https://nodejs.org/ with npm enabled.
echo [ACTION] Then close this window and double-click start-dashboard.bat again.
goto failure

:node_install_error
echo [ERROR] Node.js installation did not complete.
echo [ACTION] Install Node.js LTS from https://nodejs.org/ and run this file again.
goto failure

:restart_needed
echo [ACTION] Close this window and run start-dashboard.bat again to refresh PATH.
echo [ACTION] If it still fails, install Node.js LTS from https://nodejs.org/.
goto failure

:incomplete_project
echo [ERROR] Extract the complete repository before running this file.
echo [INFO] Keep start-dashboard.bat beside package.json and the scripts folder.
goto failure

:folder_error
echo [ERROR] Could not open the project folder.
pause
exit /b 1

:failure
pause
popd
exit /b 1
