<#
    get_events.ps1 - events as NDJSON, one line per record.

    Deliberate decisions:

    * NO "Get-WinEvent | ConvertTo-Json" on the whole result. That collects the
      entire pipeline in memory before the first line comes out. Instead
      ConvertTo-Json per record inside ForEach-Object: real streaming, the
      calling process can abort at any time and keeps what was already read.
    * Timestamps are ALWAYS formatted here. Windows PowerShell 5.1 serializes
      DateTime as /Date(1757...)/, PowerShell 7 as ISO-8601. With our own
      formatting the PS version does not matter at this point.
    * Errors are reported by the .NET TYPE NAME and FullyQualifiedErrorId, never
      by the message text. Error messages are localized; parsing them builds a
      bug with a timer.
    * -Depth 4, because the default is 2 and the property array would otherwise
      appear as a type name instead of a value.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $LogName,
    [string] $Path,
    [Parameter(Mandatory = $true)][string] $StartUtc,
    [Parameter(Mandatory = $true)][string] $EndUtc,
    # Lists as a '|'-separated string, not as [int[]]: via -File,
    # "1001,4624,..." fails the type conversion (PS 5.1, observed).
    [string] $EventIds = '',
    [string] $XmlForIds = '',
    [int] $MaxRecords = 0
)

function Split-IdList([string] $value) {
    if (-not $value) { return @() }
    return @($value.Split('|') | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
             ForEach-Object { [int]$_ })
}
[int[]] $eventIdList = @(Split-IdList $EventIds)
[int[]] $xmlIdList   = @(Split-IdList $XmlForIds)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$script:Read      = 0
$script:FirstUtc  = $null
$script:LastUtc   = $null
$script:Exception = $null
$script:ErrorId   = $null
$script:Truncated = $false
$xmlSet = @{}
foreach ($i in $xmlIdList) { $xmlSet[[int]$i] = $true }

function Write-Status {
    $status = [ordered]@{
        log          = $LogName
        records      = $script:Read
        truncated    = $script:Truncated
        exception    = $script:Exception
        error_id     = $script:ErrorId
        covered_from = $script:FirstUtc
        covered_to   = $script:LastUtc
    }
    $wrapper = [ordered]@{ __status = $status }
    Write-Output ($wrapper | ConvertTo-Json -Compress -Depth 4)
}

try {
    $start = [datetime]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture,
                               [Globalization.DateTimeStyles]::AdjustToUniversal -bor
                               [Globalization.DateTimeStyles]::AssumeUniversal)
    $end   = [datetime]::Parse($EndUtc, [Globalization.CultureInfo]::InvariantCulture,
                               [Globalization.DateTimeStyles]::AdjustToUniversal -bor
                               [Globalization.DateTimeStyles]::AssumeUniversal)

    # FilterHashtable passes channel, period AND id list as XPath to the event
    # log API. The filtering therefore happens in the service, not here. For
    # Security that is the difference between readable and unusable.
    $filter = @{ StartTime = $start.ToLocalTime(); EndTime = $end.ToLocalTime() }
    if ($Path) { $filter['Path'] = $Path } else { $filter['LogName'] = $LogName }
    if ($eventIdList.Count -gt 0) { $filter['Id'] = $eventIdList }

    Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
        $evt = $_
        $utc = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        if ($null -eq $script:FirstUtc) { $script:FirstUtc = $utc }
        $script:LastUtc = $utc

        $sid = $null
        if ($evt.UserId) { $sid = $evt.UserId.Value }

        $props = @()
        if ($evt.Properties) {
            $props = @($evt.Properties | ForEach-Object {
                if ($null -eq $_.Value) { $null } else { [string]$_.Value }
            })
        }

        $xml = $null
        if ($xmlSet.ContainsKey([int]$evt.Id)) {
            try { $xml = $evt.ToXml() } catch { $xml = $null }
        }

        $msg = $null
        try { $msg = $evt.Message } catch { $msg = $null }

        $record = [ordered]@{
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
            xml = $xml
        }
        Write-Output ($record | ConvertTo-Json -Compress -Depth 4)

        $script:Read++
        if ($MaxRecords -gt 0 -and $script:Read -ge $MaxRecords) {
            $script:Truncated = $true
            break
        }
    }
}
catch {
    # Type name instead of text - immune to localization.
    $script:Exception = $_.Exception.GetType().FullName
    # Language-neutral: separates "no events" (NoMatchingEventsFound) from
    # "channel missing" (NoMatchingLogsFound) - both arrive as System.Exception.
    $script:ErrorId = [string]$_.FullyQualifiedErrorId
}

Write-Status
