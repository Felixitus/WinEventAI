<#
    get_events.ps1 - Ereignisse als NDJSON, eine Zeile je Record.

    Bewusste Entscheidungen:

    * KEIN "Get-WinEvent | ConvertTo-Json" auf dem Gesamtergebnis. Das sammelt die
      komplette Pipeline im Speicher, bevor die erste Zeile herauskommt. Stattdessen
      ConvertTo-Json je Record innerhalb von ForEach-Object: echtes Streaming, der
      aufrufende Prozess kann jederzeit abbrechen und behaelt das bereits Gelesene.
    * Zeitstempel werden IMMER selbst formatiert. Windows PowerShell 5.1
      serialisiert DateTime als /Date(1757...)/ , PowerShell 7 als ISO-8601.
      Durch die eigene Formatierung ist die PS-Version an dieser Stelle egal.
    * Fehler werden ueber den .NET-TYPNAMEN gemeldet, nie ueber den Meldungstext.
      Fehlermeldungen sind lokalisiert; wer sie parst, baut einen Bug mit Zeitzuender.
    * -Depth 4, weil der Default 2 ist und das Property-Array sonst als Typname
      statt als Wert erscheint.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $LogName,
    [string] $Path,
    [Parameter(Mandatory = $true)][string] $StartUtc,
    [Parameter(Mandatory = $true)][string] $EndUtc,
    # Listen als '|'-getrennte Zeichenkette, nicht als [int[]]: Ueber -File
    # scheitert "1001,4624,..." an der Typumwandlung (PS 5.1, beobachtet).
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

    # FilterHashtable reicht Kanal, Zeitraum UND ID-Liste als XPath an die
    # Event-Log-API durch. Die Filterung passiert damit im Dienst, nicht hier.
    # Fuer Security ist das der Unterschied zwischen lesbar und unbrauchbar.
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
    # Typname statt Text - lokalisierungsfest.
    $script:Exception = $_.Exception.GetType().FullName
    # Sprachneutral: unterscheidet "keine Ereignisse" (NoMatchingEventsFound)
    # von "Kanal fehlt" (NoMatchingLogsFound) - beide kommen als System.Exception.
    $script:ErrorId = [string]$_.FullyQualifiedErrorId
}

Write-Status
