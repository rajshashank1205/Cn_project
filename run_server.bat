@echo off
title Mini-WireGuard Server
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required. Requesting elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo =======================================================
echo   Mini-WireGuard VPN Server
echo   Local Wi-Fi IP : 192.168.211.182
echo   UDP Port       : 51820
echo =======================================================
echo.
python server.py
pause

