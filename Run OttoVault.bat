@echo off
setlocal
cd /d "%~dp0"

rem --- find Python (the "py" launcher first, then "python")
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY goto nopython

rem --- first run (or after an update): make sure the one needed package is
rem     installed and new enough for Argon2id (cryptography 44 or newer)
%PY% -c "from cryptography.hazmat.primitives.kdf.argon2 import Argon2id" >nul 2>nul
if not errorlevel 1 goto launch
echo Setting up OttoVault (one-time, takes a few seconds)...
%PY% -m pip install --upgrade -r requirements.txt --quiet --disable-pip-version-check >nul 2>nul
%PY% -c "import cryptography" >nul 2>nul
if errorlevel 1 goto pipfail

:launch
where pyw >nul 2>nul
if not errorlevel 1 (start "" pyw "%~dp0app.py" & goto :eof)
where pythonw >nul 2>nul
if not errorlevel 1 (start "" pythonw "%~dp0app.py" & goto :eof)
start "" %PY% "%~dp0app.py"
goto :eof

:nopython
echo.
echo Python was not found on this computer.
echo Please install it first - see README.txt, "If Python is missing".
echo (python.org/downloads - tick "Add python.exe to PATH" during install)
echo.
pause
goto :eof

:pipfail
echo.
echo Could not install the "cryptography" package automatically.
echo Make sure you are online for this one-time step, then double-click this file again.
echo Or open a Command Prompt here and run:  py -m pip install -r requirements.txt
echo.
pause
goto :eof
