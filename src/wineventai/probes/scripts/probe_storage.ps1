<#
    probe_storage.ps1 - Gesundheit der Datentraeger und Datentraegerbelegung.

    Gemeldet werden ALLE physischen Datentraeger, nicht der eine, den der Befund
    meint. Das ist Absicht: disk 51/153 nennt in der Meldung eine Geraetepfad-
    angabe der Form \Device\Harddisk3\DR3, und die Zuordnung dieser Nummer zu
    einem PhysicalDisk-Objekt ist nicht stabil - sie wechselt mit der Reihenfolge
    der Erkennung und stimmt bei Mehrpfad- und RAID-Konfigurationen ohnehin
    nicht. Lieber alle Datentraeger mit dem ehrlichen Vermerk "die Zuordnung zum
    Befund ist offen" als ein einzelner, womoeglich falscher.

    Alles nur lesend: keine Oberflaechenpruefung, kein chkdsk, kein
    Selbsttest. Ein Selbsttest auf einem Datentraeger, der bereits E/A-Fehler
    meldet, waere genau der falsche Zeitpunkt.
#>
[CmdletBinding()]
param()

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
    $hatCmdlet = [bool] (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)

    if ($hatCmdlet) {
        foreach ($disk in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            $c = $null
            try { $c = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue } catch { }
            Emit 'datentraeger' ([ordered]@{
                name           = $disk.FriendlyName
                seriennummer   = $null   # bewusst nicht: geraet-identifizierend, fuer die Aussage ohne Wert
                medium         = [string] $disk.MediaType
                bus            = [string] $disk.BusType
                gesundheit     = [string] $disk.HealthStatus
                betriebsstatus = @($disk.OperationalStatus | ForEach-Object { [string] $_ })
                groesse_b      = $disk.Size
                abnutzung      = if ($c) { $c.Wear } else { $null }
                lesefehler     = if ($c) { $c.ReadErrorsTotal } else { $null }
                schreibfehler  = if ($c) { $c.WriteErrorsTotal } else { $null }
                temperatur_c   = if ($c) { $c.Temperature } else { $null }
                betriebsstunden = if ($c) { $c.PowerOnHours } else { $null }
                zaehler_da     = [bool] $c
            })
        }
    }
    else {
        Emit 'hinweis' ([ordered]@{
            text = 'Get-PhysicalDisk ist auf diesem System nicht verfuegbar; es wurden keine Datentraegerwerte gelesen.'
        })
    }

    # Der klassische SMART-Gesamtstatus. Liefert genau ein Bit je Datentraeger -
    # wenig, aber das wenige ist aussagekraeftig, wenn es kippt.
    try {
        foreach ($s in @(Get-CimInstance -Namespace 'root\wmi' `
                -ClassName 'MSStorageDriver_FailurePredictStatus' -ErrorAction Stop)) {
            Emit 'smart' ([ordered]@{
                instanz  = [string] $s.InstanceName
                ausfall_vorhergesagt = [bool] $s.PredictFailure
                grund    = $s.Reason
            })
        }
    }
    catch {
        Emit 'hinweis' ([ordered]@{
            text = 'SMART-Gesamtstatus nicht abrufbar (virtuelle Maschine, RAID-Controller oder fehlender Treibersupport).'
        })
    }

    if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
        foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue)) {
            if (-not $v.DriveLetter -and -not $v.FileSystemLabel) { continue }
            Emit 'volume' ([ordered]@{
                laufwerk    = if ($v.DriveLetter) { [string] $v.DriveLetter } else { $null }
                bezeichnung = $v.FileSystemLabel
                dateisystem = [string] $v.FileSystem
                gesundheit  = [string] $v.HealthStatus
                groesse_b   = $v.Size
                frei_b      = $v.SizeRemaining
            })
        }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'datentraeger'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
