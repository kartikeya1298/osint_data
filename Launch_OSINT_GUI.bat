@echo off
cd /d "%~dp0"
python osint_gui_app.py
if errorlevel 1 pause
