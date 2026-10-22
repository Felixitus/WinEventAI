<#
    export_evtx.ps1 - export original channels for the evidence bundle.

    The hash in the manifest is later taken over THESE files, not over our JSON
    extract: otherwise one hashes one's own interpretation instead of the
    evidence.

    Caution: without /q, 'wevtutil epl' exports the WHOLE channel, not the time
    window. If an XPath is passed, the exported file is already a selection -
    that belongs in the manifest, and that is exactly what this script writes
    into its status line.
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
