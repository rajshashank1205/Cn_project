@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo Enabling ICMP Ping in Windows Defender Firewall...
netsh advfirewall firewall add rule name="Allow-ICMP-In" protocol=icmpv4:8,any dir=in action=allow
powershell -Command "Enable-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)'"
echo [+] Ping allowed!
timeout /t 3

