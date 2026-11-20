@echo off
cd /d "%~dp0"
echo MADRIX-Diagnose wird gestartet (nur lesend, ca. 1-2 Minuten)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0MADRIX-Diagnose.ps1"
echo.
pause
