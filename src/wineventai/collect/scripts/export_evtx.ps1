<#
    export_evtx.ps1 - Originalkanaele fuer das Evidenz-Bundle exportieren.

    Der Hash im Manifest geht spaeter ueber DIESE Dateien, nicht ueber unseren
    JSON-Auszug: sonst hasht man die eigene Interpretation statt der Evidenz.

    Achtung: 'wevtutil epl' exportiert ohne /q den GESAMTEN Kanal, nicht das
    Zeitfenster. Wird ein XPath uebergeben, ist die exportierte Datei bereits
    eine Auswahl - das gehoert dann ins Manifest, und genau das schreibt dieses
    Skript in seine Statuszeile.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $LogName,
    [Parameter(Mandatory = $true)][string] $Target,
    [string] $XPath
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$exception = $null
$filtered  = $false
$size      = 0

try {
    $arguments = @('epl', $LogName, $Target, '/ow:true')
    if ($XPath) { $arguments += "/q:$XPath"; $filtered = $true }
    $output = & wevtutil.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw [System.InvalidOperationException]::new("wevtutil exit $LASTEXITCODE : $output")
    }
    if (Test-Path -LiteralPath $Target) { $size = (Get-Item -LiteralPath $Target).Length }
}
catch {
    $exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{
    log       = $LogName
    records   = 0
    truncated = $filtered
    exception = $exception
    target    = $Target
    size_b    = $size
}
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
