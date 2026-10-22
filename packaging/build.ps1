<#
    build.ps1 - baut die Auslieferung und gibt deren SHA-256 aus.

    Ohne Code-Signing-Zertifikat bleibt SmartScreen ein Aergernis. Der Weg
    drumherum ist nicht ein OV-Zertifikat (das baut Reputation erst ueber
    Download-Zahlen auf und hilft intern kaum), sondern: Verteilung ueber
    internen Share oder Softwareverteilung, mit dokumentierter Pruefsumme.
    Genau die gibt dieses Skript am Ende aus - damit sie nicht von Hand
    entsteht.
#>
[CmdletBinding()]
param(
    [string] $OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    Write-Host 'Pruefe Umgebung ...' -ForegroundColor Cyan
    python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller fehlt. pip install pyinstaller' }

    Write-Host 'Tests ...' -ForegroundColor Cyan
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Tests fehlgeschlagen. Kein Build.' }

    Write-Host 'Linter ...' -ForegroundColor Cyan
    python -m ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'Linter fehlgeschlagen. Kein Build.' }

    Write-Host 'Baue one-dir ...' -ForegroundColor Cyan
    Remove-Item -Recurse -Force build, $OutDir -ErrorAction SilentlyContinue
    pyinstaller (Join-Path $PSScriptRoot 'wineventai.spec') --noconfirm --distpath $OutDir
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller fehlgeschlagen.' }

    $version = (python -c "import sys; sys.path.insert(0,'src'); import wineventai; print(wineventai.__version__)").Trim()
    $archive = Join-Path $OutDir "wineventai-$version-win64.zip"
    Write-Host "Packe $archive ..." -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $OutDir 'wineventai\*') -DestinationPath $archive -Force

    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
    Write-Host ''
    Write-Host 'Auslieferung fertig.' -ForegroundColor Green
    Write-Host "  Datei  : $archive"
    Write-Host "  SHA-256: $hash"
    Write-Host ''
    Write-Host 'Diese Pruefsumme mit der Auslieferung dokumentieren.' -ForegroundColor Yellow
    Write-Host 'Nicht per Download verteilen, sondern ueber internen Share oder' -ForegroundColor Yellow
    Write-Host 'Softwareverteilung - SmartScreen kennt die unsignierte EXE nicht.' -ForegroundColor Yellow
}
finally {
    Pop-Location
}
