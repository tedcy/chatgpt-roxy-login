@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto run
where py >nul 2>nul
if errorlevel 1 goto python
py -3 -m venv .venv
goto install
:python
python -m venv .venv
:install
if not exist ".venv\Scripts\python.exe" goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
goto launch
:run
".venv\Scripts\python.exe" -c "from importlib.metadata import version; from pathlib import Path; import tkinter; raise SystemExit(any(version(n)!=v for n,v in (line.strip().split('==') for line in Path('requirements.txt').read_text().splitlines() if line.strip())))" >nul 2>nul
if errorlevel 1 goto install
:launch
".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info[:2] < (3,10))" >nul 2>nul
if errorlevel 1 goto failed
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo Startup failed. See the specific error above.
pause
exit /b 1
