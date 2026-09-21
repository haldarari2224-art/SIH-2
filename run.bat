@echo off
title IPsec Sentinel — Unified Full-Stack Application
cd /d "%~dp0\backend"
echo ==========================================================
echo     IPsec Sentinel: Unified Full-Stack Application
echo ==========================================================
echo [!] Serving both React Dashboard and FastAPI on:
echo     http://localhost:8000
echo ==========================================================
python main.py
pause
