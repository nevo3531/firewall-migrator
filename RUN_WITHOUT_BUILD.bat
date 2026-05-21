@echo off
title FireWall Migrator Pro
echo.
echo  Firewall Migrator Pro - Starting...
echo.
pip install flask flask-cors paramiko --quiet 2>nul
python app.py
pause
