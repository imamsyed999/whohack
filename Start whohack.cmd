@echo off
setlocal
cd /d "%~dp0"
if /i "%~1"=="build" goto pythonbuild
if exist "whohack.exe" (
  "whohack.exe" %*
  goto done
)
if exist "target\release\whohack-launcher.exe" (
  "target\release\whohack-launcher.exe" %*
  goto done
)
if exist "target\debug\whohack-launcher.exe" (
  "target\debug\whohack-launcher.exe" %*
  goto done
)
:pythonbuild
where py >nul 2>nul
if errorlevel 1 goto python
py -3 tools\windows\launch.py %*
goto done
:python
python tools\windows\launch.py %*
:done
if errorlevel 1 (
  echo.
  echo whohack could not complete this command. See the error above.
  pause
  exit /b 1
)
