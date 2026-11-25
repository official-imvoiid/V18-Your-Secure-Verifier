@echo off
setlocal
title V18 setup

rem Ask Windows for administrator rights, then start again with them.
rem No ( ) blocks around the path: a folder like "V18 (1)" would end such a block early.
net session >nul 2>&1
if %errorlevel% equ 0 goto :elevated

echo.
echo  V18 setup needs administrator rights to install its tools.
echo  Click "Yes" in the window that appears.
echo.
set "V18_SETUP_SELF=%~f0"
powershell -NoProfile -Command "Start-Process -FilePath $env:V18_SETUP_SELF -Verb RunAs"
exit /b

:elevated
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\setup\setup.ps1"
echo.
echo  Setup has finished. Read the summary above.
echo  The full log is in setup-log.txt in this folder.
echo.
pause
