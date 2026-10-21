@echo off
setlocal
cd /d "%~dp0"
rem Explicit local upgrade entry point. Never change Windows security policy.
powershell.exe -NoProfile -Command "if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }"
if errorlevel 1 (
  echo Right-click Update whohack.cmd and choose Run as administrator.
  echo Native file-read monitoring needs Windows administrator consent.
  pause
  exit /b 1
)
set "whohack_launcher=target\release\whohack-launcher.exe"
set "whohack_service=target\release\whohack-service.exe"
if exist "whohack.exe" (
  set "whohack_launcher=whohack.exe"
  set "whohack_service=bin\whohack-service.exe"
)
if not exist "%whohack_launcher%" goto missing
if not exist "%whohack_service%" goto missing
if not exist ".vigil\windows\config.toml" goto start
rem Validate before requesting a graceful stop. Existing config/rules stay intact.
"%whohack_service%" --config ".vigil\windows\config.toml" --check-config
if errorlevel 1 goto failed
"%whohack_launcher%" stop
if errorlevel 1 goto failed
set "whohack_stopped=1"
:start
"%whohack_launcher%" start
if errorlevel 1 goto failed
"%whohack_launcher%" status
echo.
echo whohack has started. Check Download activity and Protection settings.
pause
exit /b 0
:missing
echo The complete whohack Windows build is required in this folder.
:failed
echo.
echo Update did not complete. Inspect .vigil\windows\launcher.log.
echo Keep Windows security enabled. Your configuration and saved data were preserved.
if defined whohack_stopped if exist "target\release\vigil-launcher.exe" (
  echo Trying the preserved previous native build so monitoring can continue.
  "target\release\vigil-launcher.exe" start --root "%CD%"
)
pause
exit /b 1
