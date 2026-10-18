@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" start-local.py %*
) else (
    py -3 start-local.py %*
)
