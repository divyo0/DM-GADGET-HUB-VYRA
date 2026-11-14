@echo off
setlocal
cd /d "%~dp0"
title DM GADGET HUB - VYRA Risk OS
color 0B
echo.
echo ===============================================
echo   DM - GADGET HUB / VYRA Risk OS 2.0
echo   Owner: Divy Mathur
 echo ===============================================
echo.
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python environment...
  where py >nul 2>&1
  if not errorlevel 1 (
    py -3.12 -m venv .venv 2>nul
    if errorlevel 1 py -3.11 -m venv .venv 2>nul
    if errorlevel 1 py -3 -m venv .venv
  ) else (python -m venv .venv)
  if errorlevel 1 goto :failed
)
echo Installing and checking required packages...
".venv\Scripts\python.exe" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 goto :failed
if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Created local .env settings file.
)
".venv\Scripts\python.exe" setup_owner.py
if errorlevel 1 goto :failed
start "" "http://127.0.0.1:8765"
echo.
echo Starting VYRA on http://127.0.0.1:8765
echo Keep this window open. Ctrl+C to stop.
".venv\Scripts\python.exe" app.py
pause
exit /b 0
:failed
echo.
echo Setup failed. Check Python 3.10+ is installed and your internet connection is available.
pause
exit /b 1
