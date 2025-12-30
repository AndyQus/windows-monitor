@echo off
REM ===== Windows Monitor Starter (Admin) =====

:: Prüfen, ob Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Starte mit Administratorrechten...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d C:\Softwareentwicklung\windows-monitor

call .venv\Scripts\activate.bat
python src\monitor.py
