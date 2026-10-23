@echo off
rem E-TAP Sandbox Agent launcher: double-click, or run with a command
rem (setup, pair, run, test, status, forget) and options such as --server URL.
cd /d "%~dp0"
if exist "%~dp0__main__.py" cd ..
where py >nul 2>nul && (py -3 -m sandbox_agent %*) || (python -m sandbox_agent %*)
pause
