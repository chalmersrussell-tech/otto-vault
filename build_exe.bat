@echo off
rem Convenience wrapper: builds OttoVault.exe (see build_exe.ps1 for details).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_exe.ps1" %*
pause
