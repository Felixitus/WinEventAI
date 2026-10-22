<#
    list_channels.ps1 - prueft, ob konfigurierte Ereigniskanaele existieren.

    Grundlage fuer 'wineventai doctor'. Ein Filter auf einen nicht existierenden
    Kanal meldet sonst "keine Befunde" - die schlimmste Fehlerart in diesem
    Werkzeug. Deshalb wird die Konfiguration gegen das System geprueft, bevor
    irgendetwas ausgewertet wird.

    Frueher: "Get-WinEvent -ListLog * -ErrorAction Stop". Ohne Adminrechte
    bricht das beim ersten Kanal ab, dessen Metadaten nicht lesbar sind (auf
    Windows 11 beobachtet) - danach galten Application, Setup und andere als
    "FEHLT". Jetzt wird jeder Name einzeln abgefragt und das Ergebnis ueber die
    sprachneutrale FullyQualifiedErrorId unterschieden:

      NoMatchingLogsFound  -> missing     (Kanal gibt es nicht)
      LogInfoUnavailable   -> unreadable  (Kanal gibt es, Metadaten ohne Rechte nicht lesbar)

    Eine Zeile je Name:  {"name": ..., "state": "present|missing|unreadable|error", ...}
#>
[CmdletBinding()]
param(
    # '|'-getrennt, siehe collect/shell.py LIST_SEPARATOR.
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
