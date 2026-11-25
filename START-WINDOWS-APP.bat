@echo off
setlocal
title V18 Windows app
cd /d "%~dp0"

if not exist "windows\node_modules" (
  echo.
  echo  V18 is not set up on this PC yet.
  echo  Double-click SETUP.bat first, then try again.
  echo.
  pause
  exit /b 1
)

echo  Starting the V18 Windows app. Start V18 first ^(START-V18.bat^) so the app has a server to talk to.
npm start --prefix windows
