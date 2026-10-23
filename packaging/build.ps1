<#
    build.ps1 - builds the release and prints its SHA-256.

    Output in dist\:
      WinEventAI-Setup-<version>.exe   the download for end users: double-click, done
      wineventai-<version>-win64.zip   the same program without installer (portable)
      SHA256SUMS.txt                   checksums of both

    Without a code-signing certificate SmartScreen remains a nuisance. The way
    around it is not an OV certificate (it only builds reputation through
    download numbers and hardly helps internally) but: distribution with a
    documented checksum. That is exactly what this script prints at the end -
    so that it is not produced by hand.

    The Setup.exe needs Inno Setup 6 (free, jrsoftware.org; per user:
    winget install JRSoftware.InnoSetup --scope user). Without it the ZIP is
    still built and the script says that the installer is missing.
#>
[CmdletBinding()]
param(
    [string] $OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

function Find-Iscc {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    $found = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if ($found) { return $found }
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

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

    $bundle = Join-Path $OutDir 'wineventai'
    Write-Host 'Licences ...' -ForegroundColor Cyan
    python (Join-Path $PSScriptRoot 'collect_licenses.py') $bundle
    if ($LASTEXITCODE -ne 0) { throw 'Licence texts incomplete. No release without them.' }

    $version = (python -c "import sys; sys.path.insert(0,'src'); import wineventai; print(wineventai.__version__)").Trim()
    $archive = Join-Path $OutDir "wineventai-$version-win64.zip"
    Write-Host "Packing $archive ..." -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $bundle '*') -DestinationPath $archive -Force
    $artifacts = @($archive)

    $iscc = Find-Iscc
    if ($iscc) {
        Write-Host "Building installer with $iscc ..." -ForegroundColor Cyan
        & $iscc "/DAppVersion=$version" /Q (Join-Path $PSScriptRoot 'installer.iss')
        if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed.' }
        $artifacts = @((Join-Path $OutDir "WinEventAI-Setup-$version.exe")) + $artifacts
    }
    else {
        Write-Host 'Inno Setup not found - only the ZIP was built.' -ForegroundColor Yellow
    }

    $sums = foreach ($file in $artifacts) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        "$hash  $(Split-Path -Leaf $file)"
    }
    $sumsFile = Join-Path $OutDir 'SHA256SUMS.txt'
    Set-Content -LiteralPath $sumsFile -Value $sums -Encoding ascii

    Write-Host ''
    Write-Host 'Release ready.' -ForegroundColor Green
    foreach ($line in $sums) { Write-Host "  $line" }
    Write-Host ''
    Write-Host 'Publish SHA256SUMS.txt with the release.' -ForegroundColor Yellow
    Write-Host 'The EXE files are not code-signed - SmartScreen does not know them.' -ForegroundColor Yellow
}
finally {
    Pop-Location
}
