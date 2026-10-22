<#
    probe_services.ps1 - Aktueller Zustand benannter Dienste.

    Gesucht wird ueber den ANZEIGENAMEN, nicht ueber den Dienstnamen. Grund:
    Der Name kommt aus SCM 7031/7034, und dort steht in properties[0] der
    Anzeigename - auf einem deutschen System also "Druckwarteschlange" und
    nicht "Spooler". Wer hier auf -Name filtert, findet auf jedem
    nicht-englischen Windows nichts.

    Abgefragt wird Win32_Service statt Get-Service: State und StartMode sind
    dort feste WMI-Bezeichner ("Running", "Auto", "Disabled") und keine
    uebersetzten Anzeigetexte. Dieselbe Ueberlegung wie bei den numerischen
    Level-Werten im Collector.

    Alles nur lesend. Kein Start, kein Stopp, keine Aenderung des Starttyps.
#>
[CmdletBinding()]
param(
    # '|'-getrennt statt [string[]]: Ueber -File gebunden kaeme sonst nur der
    # erste Name an, die uebrigen scheitern als Positionsparameter.
    [Parameter(Mandatory = $true)]
    [string] $DisplayName
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$script:Exception = $null
$script:Emitted = 0

function Emit([string] $Kind, $Payload) {
    $wrapper = [ordered]@{ kind = $Kind }
    foreach ($entry in $Payload.GetEnumerator()) { $wrapper[$entry.Key] = $entry.Value }
    Write-Output ($wrapper | ConvertTo-Json -Compress -Depth 5)
    $script:Emitted++
}

try {
    # Einmal alles holen und in PowerShell vergleichen. Ein WQL-Filter mit einem
    # Anzeigenamen aus einer Ereignismeldung waere eine Einladung fuer
    # Anfuehrungszeichen im Namen.
    $alle = @(Get-CimInstance Win32_Service -ErrorAction Stop)

    foreach ($gesucht in @($DisplayName.Split('|') | Where-Object { $_.Trim() })) {
        if ([string]::IsNullOrWhiteSpace($gesucht)) { continue }
        $treffer = $alle | Where-Object {
            $_.DisplayName -eq $gesucht -or $_.Name -eq $gesucht
        } | Select-Object -First 1

        if (-not $treffer) {
            Emit 'dienst' ([ordered]@{
                gesucht  = $gesucht
                gefunden = $false
            })
            continue
        }

        Emit 'dienst' ([ordered]@{
            gesucht      = $gesucht
            gefunden     = $true
            name         = $treffer.Name
            anzeigename  = $treffer.DisplayName
            zustand      = [string] $treffer.State
            starttyp     = [string] $treffer.StartMode
            konto        = [string] $treffer.StartName
            prozess_id   = $treffer.ProcessId
            exit_code    = $treffer.ExitCode
            verzoegert   = [bool] $treffer.DelayedAutoStart
        })
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'dienste'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
