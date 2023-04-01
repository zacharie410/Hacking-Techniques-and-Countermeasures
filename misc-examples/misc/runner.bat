@echo off
echo Launching test_exe with elevated privileges...
echo.

set "params=%*"
set "batchPath=%~dp0"
set "exePath=%batchPath%test_exe.exe"

:: Launch test_exe with elevated privileges
elevate.exe "%exePath%" %params%

echo.
echo Done.
pause
