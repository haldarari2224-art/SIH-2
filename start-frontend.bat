@echo off
title IPsec Sentinel — Frontend Dashboard
cd /d "%~dp0\frontend"
echo [!] Launching IPsec Sentinel Dashboard on http://localhost:3000 ...
npm run dev -- --port 3000
pause
