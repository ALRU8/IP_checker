$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) { throw 'Install Python 3.11+ and reopen the terminal.' }
& $python.Source (Join-Path $PSScriptRoot 'vpn_guard.py')
exit $LASTEXITCODE
