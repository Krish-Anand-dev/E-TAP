@echo off
rem E-TAP Sandbox Agent launcher: double-click, or run with a command
rem (setup, pair, run, check, test, status, forget) and options such as --server URL.
cd /d "%~dp0"
rem Inside the repository this file sits in the package folder; the package is run from its parent.
if exist "__main__.py" cd ..

if not exist "sandbox_agent\__main__.py" (
    echo.
    echo The "sandbox_agent" folder was not found next to this file.
    echo This usually means start-agent.cmd was opened from inside the zip.
    echo.
    echo   1. Close this window.
    echo   2. Right-click the downloaded zip and choose "Extract All...".
    echo   3. Open the extracted "E-TAP Sandbox Agent" folder and double-click start-agent.cmd there.
    echo.
    pause
    exit /b 1
)

set "PYCMD="
where py >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD where python >nul 2>nul && set "PYCMD=python"
if not defined PYCMD (
    echo.
    echo Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" in the installer, then double-click this file again.
    echo.
    pause
    exit /b 1
)

%PYCMD% -m sandbox_agent %*
pause
