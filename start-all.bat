@echo off
title IPsec Sentinel — Multi-Service Launcher
echo =======================================================
echo    IPsec Sentinel: AI-Powered VPN Security Framework
echo       Smart India Hackathon (SIH) Demo Launcher
echo =======================================================
echo [1/2] Launching Backend Server in new window...
start "IPsec Sentinel Backend" cmd /c "%~dp0start-backend.bat"

echo [2/2] Launching Frontend Dashboard in new window...
start "IPsec Sentinel Frontend" cmd /c "%~dp0start-frontend.bat"

echo.
echo All services launched!
echo Access the Dashboard at: http://localhost:3000
echo Access API Docs at:     http://localhost:8000/docs
echo =======================================================
pause
