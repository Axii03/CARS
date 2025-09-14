@echo off
REM Start statclient.exe as normal user
start "" "C:\Users\Achala\Desktop\Research\CARS\dist\static_client.exe"

REM Start syslogger.exe as administrator
powershell -Command "Start-Process 'C:\Users\Achala\Desktop\Research\CARS\dist\syslogger.exe' -Verb RunAs"