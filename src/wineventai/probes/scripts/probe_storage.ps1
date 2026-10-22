<#
    probe_storage.ps1 - health of the disks and disk usage.

    ALL physical disks are reported, not the one the finding means. That is on
    purpose: disk 51/153 names a device path in the form
    \Device\Harddisk3\DR3 in its message, and mapping this number to a
    PhysicalDisk object is not stable - it changes with the detection order and
    is wrong with multipath and RAID configurations anyway. Better all disks
    with the honest note "the attribution to the finding is open" than a
    single, possibly wrong one.

    Read-only throughout: no surface scan, no chkdsk, no self-test. A self-test
    on a disk that already reports I/O errors would be exactly the wrong moment.
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
    $hasCmdlet = [bool] (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)

    if ($hasCmdlet) {
        foreach ($disk in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            $c = $null
            try { $c = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue } catch { }
            Emit 'disk' ([ordered]@{
                name               = $disk.FriendlyName
                serial_number      = $null   # deliberately not: identifies the device, no value for the statement
                media              = [string] $disk.MediaType
                bus                = [string] $disk.BusType
                health             = [string] $disk.HealthStatus
                operational_status = @($disk.OperationalStatus | ForEach-Object { [string] $_ })
                size_b             = $disk.Size
                wear               = if ($c) { $c.Wear } else { $null }
                read_errors        = if ($c) { $c.ReadErrorsTotal } else { $null }
                write_errors       = if ($c) { $c.WriteErrorsTotal } else { $null }
                temperature_c      = if ($c) { $c.Temperature } else { $null }
                power_on_hours     = if ($c) { $c.PowerOnHours } else { $null }
                counters_available = [bool] $c
            })
        }
    }
    else {
        Emit 'note' ([ordered]@{
            text = 'Get-PhysicalDisk is not available on this system; no disk values were read.'
        })
    }

    # The classic overall SMART status. Delivers exactly one bit per disk -
    # little, but that little is meaningful when it flips.
    try {
        foreach ($s in @(Get-CimInstance -Namespace 'root\wmi' `
                -ClassName 'MSStorageDriver_FailurePredictStatus' -ErrorAction Stop)) {
            Emit 'smart' ([ordered]@{
                instance          = [string] $s.InstanceName
                failure_predicted = [bool] $s.PredictFailure
                reason            = $s.Reason
            })
        }
    }
    catch {
        Emit 'note' ([ordered]@{
            text = 'Overall SMART status not available (virtual machine, RAID controller or missing driver support).'
        })
    }

    if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
        foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue)) {
            if (-not $v.DriveLetter -and -not $v.FileSystemLabel) { continue }
            Emit 'volume' ([ordered]@{
                drive       = if ($v.DriveLetter) { [string] $v.DriveLetter } else { $null }
                label       = $v.FileSystemLabel
                file_system = [string] $v.FileSystem
                health      = [string] $v.HealthStatus
                size_b      = $v.Size
                free_b      = $v.SizeRemaining
            })
        }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'storage'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
