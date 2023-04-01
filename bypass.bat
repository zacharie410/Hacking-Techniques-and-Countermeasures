@echo off
set "scriptdir=%~dp0"

:: Prompt for admin permission%scriptdir%su\SuperUser64.exe /c powershell 
powershell.exe -ExecutionPolicy Bypass -File "%scriptdir%ps_scripts\Forms.ps1"

:: Wait for the user account creation to complete
powershell.exe -ExecutionPolicy Bypass -File "%scriptdir%ps_scripts\CreateNewUser.ps1"

pause
