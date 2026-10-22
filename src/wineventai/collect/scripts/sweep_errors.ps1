<#
    sweep_errors.ps1 - critical/error events from every active channel as NDJSON.

    Flow and line kinds:

      {"__plan":    {"channels": [...], "skipped": {...}}}   exactly once, first
      { record }                                             per event
      {"__channel": {"log": ..., "records": n, "exception": ...}}  after each channel
      {"__status":  {...}}                                   at the end

    Deliberate decisions:

    * The plan comes BEFORE the first record. If the calling process aborts on
      its time limit, it therefore knows which channels were never reached -
      and reports them as timed out instead of empty.
    * Filtering uses the numeric level in the FilterHashtable, i.e. inside the
      event log service. LevelDisplayName is localized and useless.
    * LogType is compared by the enum NAME ("Operational"), which is not
      translated.
    * -ListLog runs with SilentlyContinue instead of Stop: without admin rights
      individual channels are not readable, and Stop would abort the whole list
      at the first of them. The unreadable ones are counted and reported.
    * Lists arrive as a '|'-separated string, not as [string[]]: the array
      conversion via -File is not reliable (observed failing for [int[]]).
    * No event XML: the sweep is meant to be broad and cheap. Where EventData is
      needed, the channel belongs in the fixed channel list.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $StartUtc,
    [Parameter(Mandatory = $true)][string] $EndUtc,
    [Parameter(Mandatory = $true)][string] $Levels,
    [Parameter(Mandatory = $true)][string] $LogTypes,
    [string] $Exclude = ''
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$script:Total     = 0
$script:Exception = $null

function Split-Arg([string] $value) {
    if (-not $value) { return @() }
    return @($value.Split('|') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Write-Line($payload) {
    Write-Output ($payload | ConvertTo-Json -Compress -Depth 4)
}

try {
    $start = [datetime]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture,
                               [Globalization.DateTimeStyles]::AdjustToUniversal -bor
                               [Globalization.DateTimeStyles]::AssumeUniversal)
    $end   = [datetime]::Parse($EndUtc, [Globalization.CultureInfo]::InvariantCulture,
                               [Globalization.DateTimeStyles]::AdjustToUniversal -bor
                               [Globalization.DateTimeStyles]::AssumeUniversal)

    [int[]] $levelList = @(Split-Arg $Levels | ForEach-Object { [int]$_ })

    # PowerShell hashtables compare keys case-insensitively - just like
    # Windows does with channel names.
    $typeSet = @{}
    foreach ($t in (Split-Arg $LogTypes)) { $typeSet[$t] = $true }
    $excludeSet = @{}
    foreach ($e in (Split-Arg $Exclude)) { $excludeSet[$e] = $true }

    $skipped = [ordered]@{ disabled = 0; type = 0; excluded = 0; empty = 0; unreadable = 0 }
    $listErrors = $null
    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue -ErrorVariable listErrors)
    # Only the FullyQualifiedErrorId "LogInfoUnavailable" is counted - it is
    # language-neutral and appears (observed on Windows 11 / PS 5.1) exactly
    # once per channel whose metadata the run may not read.
    if ($listErrors) {
        $skipped.unreadable = @($listErrors | Where-Object {
            $_.FullyQualifiedErrorId -like 'LogInfoUnavailable*'
        }).Count
    }

    $planned = New-Object System.Collections.Generic.List[string]
    foreach ($log in $logs) {
        if ($excludeSet.ContainsKey($log.LogName))      { $skipped.excluded++; continue }
        if (-not $log.IsEnabled)                         { $skipped.disabled++; continue }
        if (-not $typeSet.ContainsKey([string]$log.LogType)) { $skipped.type++; continue }
        # RecordCount is $null if the metadata is not readable. The channel is
        # queried anyway - it then reports its own error.
        if ($null -ne $log.RecordCount -and $log.RecordCount -eq 0) { $skipped.empty++; continue }
        $planned.Add($log.LogName)
    }

    Write-Line ([ordered]@{ __plan = [ordered]@{ channels = @($planned); skipped = $skipped } })

    foreach ($name in $planned) {
        $count = 0
        $channelException = $null
        $channelErrorId = $null
        try {
            $filter = @{
                LogName   = $name
                Level     = $levelList
                StartTime = $start.ToLocalTime()
                EndTime   = $end.ToLocalTime()
            }
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
                $evt = $_
                $utc = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')

                $sid = $null
                if ($evt.UserId) { $sid = $evt.UserId.Value }

                $props = @()
                if ($evt.Properties) {
                    $props = @($evt.Properties | ForEach-Object {
                        if ($null -eq $_.Value) { $null } else { [string]$_.Value }
                    })
                }

                $msg = $null
                try { $msg = $evt.Message } catch { $msg = $null }

                Write-Line ([ordered]@{
                    t   = $utc
                    ch  = $evt.LogName
                    pr  = $evt.ProviderName
                    id  = [int]$evt.Id
                    ver = $evt.Version
                    lvl = $evt.Level
                    tsk = $evt.Task
                    op  = $evt.Opcode
                    kw  = [int64]$evt.Keywords
                    cmp = $evt.MachineName
                    sid = $sid
                    rec = $evt.RecordId
                    pid = $evt.ProcessId
                    tid = $evt.ThreadId
                    msg = $msg
                    pv  = $props
                    xml = $null
                })
                $count++
            }
        }
        catch {
            # Type name and FullyQualifiedErrorId instead of text - immune to
            # localization. "No hits" is NoMatchingEventsFound.
            $channelException = $_.Exception.GetType().FullName
            $channelErrorId = [string]$_.FullyQualifiedErrorId
        }
        $script:Total += $count
        Write-Line ([ordered]@{ __channel = [ordered]@{
            log = $name; records = $count; exception = $channelException
            error_id = $channelErrorId
        } })
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

Write-Line ([ordered]@{ __status = [ordered]@{
    log = '*'; records = $script:Total; truncated = $false; exception = $script:Exception
} })
