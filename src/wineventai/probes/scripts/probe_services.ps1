<#
    probe_services.ps1 - current state of named services.

    The search is by DISPLAY NAME, not by service name. Reason: the name comes
    from SCM 7031/7034, and there properties[0] holds the display name - on a
    German system "Druckwarteschlange" and not "Spooler". Filtering on -Name
    finds nothing on any non-English Windows.

    Win32_Service is queried instead of Get-Service: State and StartMode are
    fixed WMI identifiers there ("Running", "Auto", "Disabled") and not
    translated display texts. The same consideration as with the numeric level
    values in the collector.

    Read-only throughout. No start, no stop, no change of the start type.
#>
[CmdletBinding()]
param(
    # '|'-separated instead of [string[]]: bound via -File, only the first name
    # would arrive, the others fail as positional parameters.
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
    # Fetch everything once and compare in PowerShell. A WQL filter with a
    # display name taken from an event message would be an invitation for
    # quotation marks in the name.
    $all = @(Get-CimInstance Win32_Service -ErrorAction Stop)

    foreach ($searched in @($DisplayName.Split('|') | Where-Object { $_.Trim() })) {
        if ([string]::IsNullOrWhiteSpace($searched)) { continue }
        $hit = $all | Where-Object {
            $_.DisplayName -eq $searched -or $_.Name -eq $searched
        } | Select-Object -First 1

        if (-not $hit) {
            Emit 'service' ([ordered]@{
                searched = $searched
                found    = $false
            })
            continue
        }

        Emit 'service' ([ordered]@{
            searched     = $searched
            found        = $true
            name         = $hit.Name
            display_name = $hit.DisplayName
            state        = [string] $hit.State
            start_mode   = [string] $hit.StartMode
            account      = [string] $hit.StartName
            process_id   = $hit.ProcessId
            exit_code    = $hit.ExitCode
            delayed      = [bool] $hit.DelayedAutoStart
        })
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'services'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
