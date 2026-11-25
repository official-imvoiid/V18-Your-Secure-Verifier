@echo off
setlocal
title V18
cd /d "%~dp0"

if not exist "server\node_modules" (
  echo.
  echo  V18 is not set up on this PC yet.
  echo  Double-click SETUP.bat first, then try again.
  echo.
  pause
  exit /b 1
)

echo.
echo  Starting V18...
echo   - V18 server:   http://localhost:8080   (window "V18 server")
echo   - Demo website: http://localhost:3000   (window "V18 demo website")
echo.
echo  To stop V18, close those two windows.
echo.

start "V18 server" cmd /k "npm run dev --prefix server"
timeout /t 10 /nobreak >nul
start "V18 demo website" cmd /k "npm start --prefix sdk-web/demo-site"
timeout /t 5 /nobreak >nul
start "" http://localhost:3000

echo  The demo website is opening in your browser.
echo  To open the Windows app, double-click START-WINDOWS-APP.bat.
echo.
timeout /t 15
