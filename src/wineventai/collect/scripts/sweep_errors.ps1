<#
    sweep_errors.ps1 - Kritisch/Fehler aus allen aktiven Kanaelen als NDJSON.

    Ablauf und Zeilenarten:

      {"__plan":    {"channels": [...], "skipped": {...}}}   genau einmal, zuerst
      { Record }                                             je Ereignis
      {"__channel": {"log": ..., "records": n, "exception": ...}}  nach jedem Kanal
      {"__status":  {...}}                                   zum Schluss

    Bewusste Entscheidungen:

    * Der Plan steht VOR dem ersten Record. Bricht der aufrufende Prozess wegen
      Zeitlimit ab, weiss er dadurch, welche Kanaele nie erreicht wurden - und
      meldet sie als abgebrochen statt als leer.
    * Gefiltert wird ueber den numerischen Level in der FilterHashtable, also im
      Event-Log-Dienst. LevelDisplayName ist lokalisiert und taugt nicht.
    * LogType wird ueber den Enum-NAMEN verglichen ("Operational"), der nicht
      uebersetzt wird.
    * -ListLog laeuft mit SilentlyContinue statt Stop: Ohne Adminrechte sind
      einzelne Kanaele nicht lesbar, und Stop wuerde die ganze Liste beim ersten
      davon abbrechen. Die nicht lesbaren werden gezaehlt und gemeldet.
    * Listen kommen als Zeichenkette mit '|' getrennt, nicht als [string[]]:
      Ueber -File ist die Array-Umwandlung nicht verlaesslich belegt.
    * Kein Event-XML: Der Sweep soll breit und billig sein. Wo EventData
      gebraucht wird, gehoert der Kanal in die feste Kanalliste.
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

    # Hashtables in PowerShell vergleichen Schluessel ohne Ruecksicht auf
    # Gross-/Kleinschreibung - genau wie Windows bei Kanalnamen.
    $typeSet = @{}
    foreach ($t in (Split-Arg $LogTypes)) { $typeSet[$t] = $true }
    $excludeSet = @{}
    foreach ($e in (Split-Arg $Exclude)) { $excludeSet[$e] = $true }

    $skipped = [ordered]@{ disabled = 0; type = 0; excluded = 0; empty = 0; unreadable = 0 }
    $listErrors = $null
    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue -ErrorVariable listErrors)
    # Gezaehlt wird nur die FullyQualifiedErrorId "LogInfoUnavailable" - sie
    # ist sprachneutral und steht (auf Windows 11 / PS 5.1 beobachtet) genau
    # einmal je Kanal, dessen Metadaten der Lauf nicht lesen darf.
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
        # RecordCount ist $null, wenn die Metadaten nicht lesbar sind. Dann wird
        # trotzdem abgefragt - der Kanal meldet seinen Fehler dann selbst.
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
            # Typname und FullyQualifiedErrorId statt Text - lokalisierungsfest.
            # "Keine Treffer" ist NoMatchingEventsFound.
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
