@echo off
cd /d "%~dp0.."
py -3 linuxguard.py || python linuxguard.py
pause
