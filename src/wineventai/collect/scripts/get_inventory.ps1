<#
    get_inventory.ps1 - Systemkontext und optionale Zusatzquellen als NDJSON.

    Liefert je nach Schaltern: Systeminventar, Datentraegergesundheit,
    installierte Updates, signierte Treiber. Alles nur lesend.
#>
[CmdletBinding()]
param(
    [switch] $DiskHealth,
    [switch] $Inventory
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$script:Exception = $null
$script:Read = 0

function Emit([string] $Kind, $Payload) {
    $wrapper = [ordered]@{ kind = $Kind; data = $Payload }
    Write-Output ($wrapper | ConvertTo-Json -Compress -Depth 6)
    $script:Read++
}

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Emit 'system' ([ordered]@{
        caption        = $os.Caption
        version        = $os.Version
        build          = $os.BuildNumber
        install_date   = if ($os.InstallDate) { $os.InstallDate.ToUniversalTime().ToString('o') } else { $null }
        last_boot      = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null }
        manufacturer   = $cs.Manufacturer
        model          = $cs.Model
        total_memory_b = $cs.TotalPhysicalMemory
        domain         = $cs.Domain
    })

    if ($DiskHealth) {
        Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
            $disk = $_
            $counters = $null
            try { $counters = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue } catch { }
            Emit 'disk' ([ordered]@{
                friendly_name    = $disk.FriendlyName
                media_type       = [string]$disk.MediaType
                health_status    = [string]$disk.HealthStatus
                operational      = [string]$disk.OperationalStatus
                size_b           = $disk.Size
                wear             = if ($counters) { $counters.Wear } else { $null }
                read_errors      = if ($counters) { $counters.ReadErrorsTotal } else { $null }
                write_errors     = if ($counters) { $counters.WriteErrorsTotal } else { $null }
                temperature_c    = if ($counters) { $counters.Temperature } else { $null }
                power_on_hours   = if ($counters) { $counters.PowerOnHours } else { $null }
            })
        }
    }

    if ($Inventory) {
        Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
            Emit 'hotfix' ([ordered]@{
                id           = $_.HotFixID
                description  = $_.Description
                installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToUniversalTime().ToString('o') } else { $null }
            })
        }
        Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.DeviceName } | ForEach-Object {
                Emit 'driver' ([ordered]@{
                    device   = $_.DeviceName
                    provider = $_.DriverProviderName
                    version  = $_.DriverVersion
                    date     = if ($_.DriverDate) { $_.DriverDate.ToUniversalTime().ToString('o') } else { $null }
                })
            }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ log = 'Inventory'; records = $script:Read; truncated = $false; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
