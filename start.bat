@echo off
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
.venv\Scripts\python.exe manage.py migrate -v 0
.venv\Scripts\python.exe manage.py bootstrap_admin
start "" http://127.0.0.1:8905/
.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8905
