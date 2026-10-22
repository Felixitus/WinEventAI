<#
    get_reliability.ps1 - Win32_ReliabilityRecords als NDJSON.

    Wichtig: Diese Klasse ist auf vielen Systemen LEER, weil der RACAgent-Task
    deaktiviert ist - auf Servern der Regelfall. "Leer" heisst hier also nicht
    "keine Vorfaelle", sondern "wird nicht erhoben". Das Skript meldet deshalb
    zusaetzlich, ob der Task ueberhaupt aktiv ist; die Auswertung macht daraus
    NOT_LOGGED statt EMPTY.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $StartUtc,
    [int] $MaxRecords = 0
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$script:Read      = 0
$script:Exception = $null
$script:ErrorId   = $null
$script:RacState  = 'unbekannt'
$script:FirstUtc  = $null
$script:LastUtc   = $null

try {
    $task = Get-ScheduledTask -TaskName 'RacTask' -TaskPath '\Microsoft\Windows\RAC\' -ErrorAction SilentlyContinue
    if ($task) { $script:RacState = [string]$task.State } else { $script:RacState = 'nicht vorhanden' }
} catch { $script:RacState = 'unbekannt' }

try {
    $start = [datetime]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture,
                               [Globalization.DateTimeStyles]::AdjustToUniversal -bor
                               [Globalization.DateTimeStyles]::AssumeUniversal)

    Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop | ForEach-Object {
        $rec = $_
        if ($null -eq $rec.TimeGenerated) { return }
        $when = $rec.TimeGenerated.ToUniversalTime()
        if ($when -lt $start) { return }

        $utc = $when.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        if ($null -eq $script:FirstUtc) { $script:FirstUtc = $utc }
        $script:LastUtc = $utc

        $record = [ordered]@{
            t   = $utc
            ch  = 'Reliability'
            pr  = $rec.SourceName
            id  = [int]$rec.EventIdentifier
            lvl = 3
            cmp = $rec.ComputerName
            msg = $rec.Message
            pv  = @([string]$rec.ProductName, [string]$rec.User, [string]$rec.Logfile)
        }
        Write-Output ($record | ConvertTo-Json -Compress -Depth 4)

        $script:Read++
        if ($MaxRecords -gt 0 -and $script:Read -ge $MaxRecords) { break }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
    $script:ErrorId   = [string]$_.FullyQualifiedErrorId
}

$status = [ordered]@{
    log          = 'Reliability'
    records      = $script:Read
    truncated    = $false
    exception    = $script:Exception
    error_id     = $script:ErrorId
    covered_from = $script:FirstUtc
    covered_to   = $script:LastUtc
    rac_state    = $script:RacState
}
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
