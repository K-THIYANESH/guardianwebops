@echo off
title Guardian Swarm Dashboard - http://127.0.0.1:5000
cd /d "%~dp0"
echo.
echo  Guardian Swarm V3 Dashboard
echo  ===========================
echo  URL: http://127.0.0.1:5000
echo.
echo  Keep this window open while using the dashboard.
echo  Press Ctrl+C to stop the server.
echo.
python app.py
pause
