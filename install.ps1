<#
    install.ps1 - WinEventAI aus DIESEM Ordner installieren.

    Warum es dieses Skript gibt: WinEventAI liegt nicht auf PyPI.
    'pip install wineventai' findet dort nichts - oder, schlimmer, etwas
    Fremdes. Installiert werden muss aus dem Projektordner, und genau das
    macht dieses Skript, inklusive der beiden Stolperstellen: eine alte
    Installation, die noch auf einen anderen Ordner zeigt, und die Frage, ob
    die Oberflaeche mit soll.

    Aufruf im Projektordner:
        powershell -ExecutionPolicy Bypass -File .\install.ps1
        powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoGui
        powershell -ExecutionPolicy Bypass -File .\install.ps1 -Venv
#>
[CmdletBinding()]
param(
    [switch] $NoGui,
    [switch] $Dev,
    [switch] $Venv
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root

function Fail([string] $Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Red
    Pop-Location
    exit 1
}

try {
    if (-not (Test-Path (Join-Path $root 'pyproject.toml'))) {
        Fail "Hier liegt keine pyproject.toml. Das Skript gehoert in den Projektordner."
    }

    # --- Python finden -------------------------------------------------------
    $python = 'python'
    if (Get-Command py -ErrorAction SilentlyContinue) { $python = 'py' }
    $version = & $python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
    Write-Host "Python $version ($python)" -ForegroundColor Cyan

    $major, $minor = $version.Split('.')
    if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 11)) {
        Fail "WinEventAI braucht Python 3.11 oder neuer. Gefunden: $version"
    }

    # --- Optional in eine eigene Umgebung ------------------------------------
    if ($Venv) {
        $venvPath = Join-Path $root '.venv'
        if (-not (Test-Path $venvPath)) {
            Write-Host "Lege virtuelle Umgebung an ..." -ForegroundColor Cyan
            & $python -m venv $venvPath
        }
        $python = Join-Path $venvPath 'Scripts\python.exe'
        Write-Host "Verwende $python" -ForegroundColor Cyan
    }

    # --- Alte Installation aus dem Weg raeumen -------------------------------
    # Eine vorhandene Installation zeigt sonst weiter auf ihren alten Ordner,
    # und 'wineventai --version' meldet hartnaeckig die alte Nummer.
    $installed = & $python -m pip show wineventai 2>$null
    if ($LASTEXITCODE -eq 0) {
        $ort = ($installed | Select-String '^Location:').ToString()
        $alt = ($installed | Select-String '^Version:').ToString()
        Write-Host "Vorhandene Installation gefunden: $alt" -ForegroundColor Yellow
        Write-Host "  $ort" -ForegroundColor Yellow
        Write-Host "Wird entfernt, damit die neue Fassung wirklich greift." -ForegroundColor Yellow
        & $python -m pip uninstall -y wineventai | Out-Null
    }

    # --- Installieren --------------------------------------------------------
    $extras = if ($Dev) { '.[dev]' } elseif ($NoGui) { '.' } else { '.[gui]' }
    Write-Host "Installiere $extras aus $root ..." -ForegroundColor Cyan
    & $python -m pip install -e $extras
    if ($LASTEXITCODE -ne 0) { Fail "pip ist fehlgeschlagen." }

    # --- Nachweisen ----------------------------------------------------------
    Write-Host ""
    & $python -m wineventai --version
    Write-Host ""

    $hatQt = & $python -c "from importlib.util import find_spec; print(find_spec('PySide6') is not None)"
    if ($hatQt.Trim() -eq 'True') {
        Write-Host "Oberflaeche verfuegbar:  wineventai gui" -ForegroundColor Green
    } else {
        Write-Host "Nur Kommandozeile installiert (ohne -NoGui gaebe es die Oberflaeche dazu)." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Naechster Schritt - Umgebung pruefen, BEVOR etwas ausgewertet wird:" -ForegroundColor Cyan
    Write-Host "    wineventai doctor"
    if ($Venv) {
        Write-Host ""
        Write-Host "Die Umgebung muss vorher aktiviert werden:" -ForegroundColor Cyan
        Write-Host "    .\.venv\Scripts\Activate.ps1"
    }
}
finally {
    Pop-Location
}
