<#
    install.ps1 - install WinEventAI from THIS folder.

    Why this script exists: WinEventAI is not on PyPI.
    'pip install wineventai' finds nothing there - or, worse, something
    foreign. It has to be installed from the project folder, and that is
    exactly what this script does, including the two stumbling blocks: an old
    installation that still points to another folder, and the question
    whether the user interface should come along.

    Call in the project folder:
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
        Fail "There is no pyproject.toml here. The script belongs in the project folder."
    }

    # --- Find Python ---------------------------------------------------------
    $python = 'python'
    if (Get-Command py -ErrorAction SilentlyContinue) { $python = 'py' }
    $version = & $python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
    Write-Host "Python $version ($python)" -ForegroundColor Cyan

    $major, $minor = $version.Split('.')
    if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 11)) {
        Fail "WinEventAI needs Python 3.11 or newer. Found: $version"
    }

    # --- Optionally into an environment of its own ---------------------------
    if ($Venv) {
        $venvPath = Join-Path $root '.venv'
        if (-not (Test-Path $venvPath)) {
            Write-Host "Creating virtual environment ..." -ForegroundColor Cyan
            & $python -m venv $venvPath
        }
        $python = Join-Path $venvPath 'Scripts\python.exe'
        Write-Host "Using $python" -ForegroundColor Cyan
    }

    # --- Move an old installation out of the way -----------------------------
    # An existing installation otherwise keeps pointing to its old folder, and
    # 'wineventai --version' stubbornly reports the old number.
    $installed = & $python -m pip show wineventai 2>$null
    if ($LASTEXITCODE -eq 0) {
        $location = ($installed | Select-String '^Location:').ToString()
        $old = ($installed | Select-String '^Version:').ToString()
        Write-Host "Existing installation found: $old" -ForegroundColor Yellow
        Write-Host "  $location" -ForegroundColor Yellow
        Write-Host "It is removed so that the new version really takes effect." -ForegroundColor Yellow
        & $python -m pip uninstall -y wineventai | Out-Null
    }

    # --- Install -------------------------------------------------------------
    $extras = if ($Dev) { '.[dev]' } elseif ($NoGui) { '.' } else { '.[gui]' }
    Write-Host "Installing $extras from $root ..." -ForegroundColor Cyan
    & $python -m pip install -e $extras
    if ($LASTEXITCODE -ne 0) { Fail "pip failed." }

    # --- Prove it ------------------------------------------------------------
    Write-Host ""
    & $python -m wineventai --version
    Write-Host ""

    $hasQt = & $python -c "from importlib.util import find_spec; print(find_spec('PySide6') is not None)"
    if ($hasQt.Trim() -eq 'True') {
        Write-Host "User interface available:  wineventai gui" -ForegroundColor Green
    } else {
        Write-Host "Command line only (without -NoGui the user interface would be included)." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Next step - check the environment BEFORE analyzing anything:" -ForegroundColor Cyan
    Write-Host "    wineventai doctor"
    Write-Host "Ollama is optional; without it the reports come from the rule engine." -ForegroundColor Cyan
    if ($Venv) {
        Write-Host ""
        Write-Host "The environment has to be activated first:" -ForegroundColor Cyan
        Write-Host "    .\.venv\Scripts\Activate.ps1"
    }
}
finally {
    Pop-Location
}
