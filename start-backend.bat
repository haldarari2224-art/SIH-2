@echo off
title IPsec Sentinel — Backend Server
cd /d "%~dp0\backend"
echo [!] Starting IPsec Sentinel FastAPI Engine on http://localhost:8000 ...
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
