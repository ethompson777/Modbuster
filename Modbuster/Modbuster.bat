@echo off
cd /d "%~dp0"
python Modbuster.py
if errorlevel 1 pause
