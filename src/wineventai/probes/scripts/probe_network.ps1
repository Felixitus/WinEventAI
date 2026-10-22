<#
    probe_network.ps1 - reachability of the local network infrastructure.

    Measurements go exclusively against addresses this script reads itself
    from the machine's IP configuration: DNS servers, default gateway, DHCP
    server. It accepts NO target address from outside. That is where the
    promise "local network only" is anchored technically and not just in the
    documentation - a caller cannot make this probe talk to anything on the
    internet.

    In addition, every address found is checked against the private ranges.
    Whoever configured 8.8.8.8 as DNS server gets no measurement for it but the
    note "public address, skipped".

    Ping via System.Net.NetworkInformation.Ping instead of Test-Connection:
    Test-Connection returns a Win32_PingStatus with the field ResponseTime in
    PowerShell 5.1 and a PingStatus with the field Latency from PowerShell 7 on.
    The .NET class is the same in both cases.

    Read-only throughout. No state change, no continuous test, no load.
#>
[CmdletBinding()]
param(
    # '|'-separated instead of [string[]]: via -File, "dns,gateway" would
    # otherwise arrive as ONE element, and -contains 'dns' would be silently false.
    [string] $Role = 'dns|gateway|dhcp',
    [int] $Count = 3,
    [int] $TimeoutMs = 1500,
    [switch] $NoDnsQuery
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$script:Exception = $null
$script:Emitted = 0
$script:Seen = @{}
$roleList = @($Role.Split('|') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })

function Emit([string] $Kind, $Payload) {
    $wrapper = [ordered]@{ kind = $Kind }
    foreach ($entry in $Payload.GetEnumerator()) { $wrapper[$entry.Key] = $entry.Value }
    Write-Output ($wrapper | ConvertTo-Json -Compress -Depth 5)
    $script:Emitted++
}

function Test-PrivateAddress([string] $Address) {
    # Language-neutral and without name resolution: only the address is checked.
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref] $parsed)) { return $false }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $o = $parsed.GetAddressBytes()
        if ($o[0] -eq 10) { return $true }
        if ($o[0] -eq 127) { return $true }
        if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
        if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
        if ($o[0] -eq 169 -and $o[1] -eq 254) { return $true }
        return $false
    }

    if ([System.Net.IPAddress]::IPv6Loopback.Equals($parsed)) { return $true }
    if ($parsed.IsIPv6LinkLocal -or $parsed.IsIPv6SiteLocal) { return $true }
    $first = $parsed.GetAddressBytes()[0]
    if (($first -band 0xFE) -eq 0xFC) { return $true }   # fc00::/7, unique local
    return $false
}

function Measure-Target([string] $RoleName, [string] $Address, [string] $Adapter) {
    $key = "$RoleName|$Address"
    if ($script:Seen.ContainsKey($key)) { return }
    $script:Seen[$key] = $true

    if (-not (Test-PrivateAddress $Address)) {
        Emit 'target' ([ordered]@{
            role     = $RoleName
            address  = $Address
            adapter  = $Adapter
            private  = $false
            skipped  = $true
            reason   = 'Address is outside the private ranges; this probe only measures within the local network.'
        })
        return
    }

    $sent = 0; $received = 0; $times = @(); $lastError = $null
    $pinger = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            $sent++
            try {
                $reply = $pinger.Send($Address, $TimeoutMs)
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $received++
                    $times += [double] $reply.RoundtripTime
                }
                else {
                    # IPStatus is an enum name, not translated text.
                    $lastError = [string] $reply.Status
                }
            }
            catch {
                $lastError = $_.Exception.GetType().FullName
            }
        }
    }
    finally {
        try { $pinger.Dispose() } catch { }
    }

    $avg = $null; $max = $null
    if ($times.Count -gt 0) {
        $avg = [math]::Round((($times | Measure-Object -Average).Average), 1)
        $max = [math]::Round((($times | Measure-Object -Maximum).Maximum), 1)
    }

    Emit 'target' ([ordered]@{
        role      = $RoleName
        address   = $Address
        adapter   = $Adapter
        private   = $true
        skipped   = $false
        sent      = $sent
        received  = $received
        avg_ms    = $avg
        max_ms    = $max
        error     = $lastError
    })
}

function Measure-DnsQuery([string] $Server, [string] $Name) {
    $start = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false; $queryError = $null; $answer = $null
    try {
        # Only the own machine name is queried. That way no foreign name leaves
        # the house, and the question is still the right one: does the server
        # SERVICE answer, not only the server HOST on ICMP.
        $result = Resolve-DnsName -Name $Name -Server $Server -DnsOnly -NoHostsFile `
            -QuickTimeout -ErrorAction Stop
        $ok = $true
        $first = $result | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($first) { $answer = [string] $first.IPAddress }
    }
    catch {
        $queryError = $_.Exception.GetType().FullName
    }
    $start.Stop()

    Emit 'dnsquery' ([ordered]@{
        server      = $Server
        name        = $Name
        success     = $ok
        answer      = $answer
        duration_ms = [math]::Round($start.Elapsed.TotalMilliseconds, 0)
        error       = $queryError
    })
}

try {
    $configs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = true' -ErrorAction Stop)

    foreach ($cfg in $configs) {
        Emit 'adapter' ([ordered]@{
            description  = $cfg.Description
            index        = $cfg.InterfaceIndex
            addresses    = @($cfg.IPAddress)
            dhcp_enabled = [bool] $cfg.DHCPEnabled
        })
    }

    if ($roleList -contains 'gateway') {
        $any = $false
        foreach ($cfg in $configs) {
            foreach ($gw in @($cfg.DefaultIPGateway)) {
                if ($gw) { $any = $true; Measure-Target 'gateway' $gw $cfg.Description }
            }
        }
        if (-not $any) {
            Emit 'empty' ([ordered]@{ role = 'gateway'; reason = 'No default gateway configured.' })
        }
    }

    if ($roleList -contains 'dhcp') {
        $any = $false
        foreach ($cfg in $configs) {
            if ($cfg.DHCPEnabled -and $cfg.DHCPServer) {
                $any = $true
                Measure-Target 'dhcp' $cfg.DHCPServer $cfg.Description
            }
        }
        if (-not $any) {
            Emit 'empty' ([ordered]@{ role = 'dhcp'; reason = 'No interface obtains its address via DHCP.' })
        }
    }

    if ($roleList -contains 'dns') {
        $servers = New-Object System.Collections.Generic.List[string]
        foreach ($cfg in $configs) {
            foreach ($dns in @($cfg.DNSServerSearchOrder)) {
                if ($dns) {
                    Measure-Target 'dns' $dns $cfg.Description
                    if (-not $servers.Contains([string] $dns)) { $servers.Add([string] $dns) }
                }
            }
        }
        if ($servers.Count -eq 0) {
            Emit 'empty' ([ordered]@{ role = 'dns'; reason = 'No DNS server configured.' })
        }
        elseif (-not $NoDnsQuery) {
            $ownName = $env:COMPUTERNAME
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                foreach ($server in $servers) {
                    if (Test-PrivateAddress $server) { Measure-DnsQuery $server $ownName }
                }
            }
            else {
                Emit 'note' ([ordered]@{
                    role = 'dns'
                    text = 'Resolve-DnsName is not available on this system; only ICMP was measured.'
                })
            }
        }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'network'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
