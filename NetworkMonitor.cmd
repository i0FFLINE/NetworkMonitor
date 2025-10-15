@echo off
cls
echo.

pwsh -NoProfileLoadTime -ExecutionPolicy Bypass -File "NetworkMonitor.ps1" -ShowUDP -ShowPorts -ShowPID -ShowProgress -DnsTimeoutMs 10000