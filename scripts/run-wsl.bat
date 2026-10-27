@echo off
cd /d "%~dp0.."
where wsl >nul 2>nul || (echo WSL is not installed. See https://learn.microsoft.com/windows/wsl/install & pause & exit /b)
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:47651/"
wsl python3 linuxguard.py --no-window
