@echo off
title Mini-WireGuard Client
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required. Requesting elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo =======================================================
echo   Mini-WireGuard VPN Client
echo   Connecting to Server at 192.168.211.182:51820...
echo =======================================================
echo.
python client.py 192.168.211.182
pause

