<#
    list_channels.ps1 - checks whether configured event channels exist.

    Basis for 'wineventai doctor'. A filter on a non-existent channel would
    otherwise report "no findings" - the worst kind of error in this tool. The
    configuration is therefore checked against the system before anything is
    analyzed.

    Previously: "Get-WinEvent -ListLog * -ErrorAction Stop". Without admin
    rights that aborts at the first channel whose metadata is not readable
    (observed on Windows 11) - afterwards Application, Setup and others counted
    as "MISSING". Now every name is queried individually and the result is told
    apart by the language-neutral FullyQualifiedErrorId:

      NoMatchingLogsFound  -> missing     (channel does not exist)
      LogInfoUnavailable   -> unreadable  (channel exists, metadata not readable without rights)

    One line per name:  {"name": ..., "state": "present|missing|unreadable|error", ...}
#>
[CmdletBinding()]
param(
    # '|'-separated, see collect/shell.py LIST_SEPARATOR.
    [Parameter(Mandatory = $true)][string] $Names
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$script:Read = 0
$script:Exception = $null

try {
    $list = @($Names.Split('|') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($name in $list) {
        $record = [ordered]@{ name = $name; state = 'present'; enabled = $null; error_id = $null }
        try {
            $log = Get-WinEvent -ListLog $name -ErrorAction Stop
            $record.enabled = [bool]$log.IsEnabled
        }
        catch {
            $id = [string]$_.FullyQualifiedErrorId
            $record.error_id = $id
            if ($id -like 'NoMatchingLogsFound*') { $record.state = 'missing' }
            elseif ($id -like 'LogInfoUnavailable*') { $record.state = 'unreadable' }
            else { $record.state = 'error' }
        }
        Write-Output ($record | ConvertTo-Json -Compress -Depth 3)
        $script:Read++
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{
    log       = '__channels__'
    records   = $script:Read
    truncated = $false
    exception = $script:Exception
}
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
