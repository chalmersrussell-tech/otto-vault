<#
 build_exe.ps1 - build a real Windows program (OttoVault.exe, no console window)
 from the source in this folder with PyInstaller.

 Usage (PowerShell, from this folder):
     .\build_exe.ps1                       # installs to %LOCALAPPDATA%\Programs\OttoVault
     .\build_exe.ps1 -OutDir D:\Apps\OttoVault

 What it does / does not do
 * Installs PyInstaller and a recent "cryptography" for the CURRENT USER only
   (pip --user). Nothing system-wide.
 * Builds in a temp folder and copies the finished program folder to -OutDir.
   Your vault (%APPDATA%\OttoVault\vault.dat) is never read, copied or bundled.
 * The .exe is NOT code-signed. Windows SmartScreen / antivirus may warn about
   an unsigned program (PyInstaller programs are a common false-positive), and
   Windows application-control policies (Smart App Control, WDAC, AppLocker)
   can refuse to run it at all. If that happens use "Run OttoVault.bat"; do
   not disable the Windows protection for this.
   Build it yourself from source you have read, and compare your build's hash
   with Get-FileHash if you want to check later copies.
 * The .exe is a convenience launcher, not a security boundary: it contains the
   same readable-by-anyone Python code, and the vault is protected by your
   master password and encryption - not by the way the program is started.
 * Rebuild after updating the source. otto_get.py / otto_add.py stay normal
   scripts and keep working with the Python on your PC.
#>
param([string]$OutDir = (Join-Path $env:LOCALAPPDATA "Programs\OttoVault"))
# Native tools (pip, PyInstaller) print progress/warnings on stderr; do not treat that as failure.
# Real failures are caught through the explicit exit-code checks below.
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $null
foreach ($c in @("py", "python")) { if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break } }
if (-not $py) { throw "Python was not found. Install Python 3.11+ first (see README.txt)." }

& $py -m pip install --user --quiet --disable-pip-version-check --no-warn-script-location --upgrade pyinstaller "cryptography>=44.0"
if ($LASTEXITCODE -ne 0) { throw "pip could not install PyInstaller (are you online?)." }

$tmp = Join-Path $env:TEMP ("ottovault-build-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
$pushed = $false
try {
    Push-Location $here; $pushed = $true
    & $py -m PyInstaller --noconfirm --clean --windowed --onedir --name OttoVault `
        --distpath (Join-Path $tmp "dist") --workpath (Join-Path $tmp "work") `
        --specpath $tmp app.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
    Pop-Location; $pushed = $false
    $built = Join-Path $tmp "dist\OttoVault"
    if (-not (Test-Path (Join-Path $built "OttoVault.exe"))) { throw "OttoVault.exe was not produced." }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    # copy over the previous build (never touches anything outside -OutDir)
    Copy-Item -Path (Join-Path $built "*") -Destination $OutDir -Recurse -Force
    Write-Host "Built: $(Join-Path $OutDir 'OttoVault.exe')"
    Write-Host ("SHA-256: " + (Get-FileHash (Join-Path $OutDir 'OttoVault.exe')).Hash)
} finally {
    if ($pushed) { Pop-Location }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
