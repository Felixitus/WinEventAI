<#
    build.ps1 - builds the release and prints its SHA-256.

    Without a code-signing certificate SmartScreen remains a nuisance. The way
    around it is not an OV certificate (it only builds reputation through
    download numbers and hardly helps internally) but: distribution via an
    internal share or software distribution, with a documented checksum.
    That is exactly what this script prints at the end - so that it is not
    produced by hand.
#>
[CmdletBinding()]
param(
    [string] $OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    Write-Host 'Checking environment ...' -ForegroundColor Cyan
    python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller is missing. pip install pyinstaller' }

    Write-Host 'Tests ...' -ForegroundColor Cyan
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed. No build.' }

    Write-Host 'Linter ...' -ForegroundColor Cyan
    python -m ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'Linter failed. No build.' }

    Write-Host 'Building one-dir ...' -ForegroundColor Cyan
    Remove-Item -Recurse -Force build, $OutDir -ErrorAction SilentlyContinue
    pyinstaller (Join-Path $PSScriptRoot 'wineventai.spec') --noconfirm --distpath $OutDir
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }

    $version = (python -c "import sys; sys.path.insert(0,'src'); import wineventai; print(wineventai.__version__)").Trim()
    $archive = Join-Path $OutDir "wineventai-$version-win64.zip"
    Write-Host "Packing $archive ..." -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $OutDir 'wineventai\*') -DestinationPath $archive -Force

    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
    Write-Host ''
    Write-Host 'Release ready.' -ForegroundColor Green
    Write-Host "  File   : $archive"
    Write-Host "  SHA-256: $hash"
    Write-Host ''
    Write-Host 'Document this checksum together with the release.' -ForegroundColor Yellow
    Write-Host 'Do not distribute by download but via internal share or' -ForegroundColor Yellow
    Write-Host 'software distribution - SmartScreen does not know the unsigned EXE.' -ForegroundColor Yellow
}
finally {
    Pop-Location
}
