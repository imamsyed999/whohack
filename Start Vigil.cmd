@echo off
rem Compatibility entry point for existing shortcuts. Product name: whohack.
call "%~dp0Start whohack.cmd" %*
exit /b %errorlevel%
