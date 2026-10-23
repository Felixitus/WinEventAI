<#
    probe_time.ps1 - current state of the Windows time service.

    Hangs on W32Time warnings (Microsoft-Windows-Time-Service 36/47/48/50/129/
    134). Three language-neutral sources, no parsing of 'w32tm /query' output -
    that output is translated:

    1. Win32_Service 'W32Time': State and StartMode are fixed WMI identifiers.
    2. The registry value Parameters\Type (NTP, NT5DS, AllSync, NoSync) and
       Parameters\NtpServer ("host,0x9 host2,0x8").
    3. A single SNTP request (RFC 4330, 48 bytes over UDP 123) to each
       configured server - but ONLY if its address is in a private range.
       time.windows.com and every other internet source are skipped: this
       probe must not create internet traffic of its own, the same promise as
       the network probe.

    Read-only throughout: an SNTP request asks for the time, it does not set
    it. No 'w32tm /resync', no service start, no registry write.
#>
[CmdletBinding()]
param(
    [int] $TimeoutMs = 1500
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

function Test-PrivateAddress([string] $Address) {
    # Same check as probe_network.ps1: only the address, no name resolution.
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
    if (($first -band 0xFE) -eq 0xFC) { return $true }
    return $false
}

function ConvertFrom-NtpTimestamp([byte[]] $Bytes, [int] $Offset) {
    # 32 bit seconds since 1900 plus 32 bit fraction, big endian.
    [uint64] $seconds = 0
    [uint64] $fraction = 0
    for ($i = 0; $i -lt 4; $i++) { $seconds = $seconds * 256 + $Bytes[$Offset + $i] }
    for ($i = 4; $i -lt 8; $i++) { $fraction = $fraction * 256 + $Bytes[$Offset + $i] }
    $epoch = New-Object DateTime(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return $epoch.AddMilliseconds(([double] $seconds) * 1000.0 + ([double] $fraction) * 1000.0 / 4294967296.0)
}

function Measure-Peer([string] $Server, [string] $Address) {
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Address, 123)
        $request = New-Object byte[] 48
        $request[0] = 0x1B   # LI 0, version 3, mode 3 (client)
        $sent = [DateTime]::UtcNow
        [void] $udp.Send($request, 48)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $reply = $udp.Receive([ref] $remote)
        $received = [DateTime]::UtcNow
        if ($reply.Length -lt 48) { throw [System.IO.InvalidDataException]::new('short reply') }

        $serverReceive = ConvertFrom-NtpTimestamp $reply 32
        $serverTransmit = ConvertFrom-NtpTimestamp $reply 40
        $offset = (($serverReceive - $sent).TotalMilliseconds + ($serverTransmit - $received).TotalMilliseconds) / 2.0
        $delay = ($received - $sent).TotalMilliseconds - ($serverTransmit - $serverReceive).TotalMilliseconds
        Emit 'peer' ([ordered]@{
            server    = $Server
            address   = $Address
            private   = $true
            skipped   = $false
            success   = $true
            stratum   = [int] $reply[1]
            offset_ms = [Math]::Round($offset, 1)
            delay_ms  = [Math]::Round($delay, 1)
            error     = $null
        })
    }
    catch {
        # PowerShell wraps .NET errors of method calls; the inner type is the
        # informative, language-neutral one (SocketException for a timeout).
        $failure = $_.Exception
        if ($failure.InnerException) { $failure = $failure.InnerException }
        Emit 'peer' ([ordered]@{
            server  = $Server
            address = $Address
            private = $true
            skipped = $false
            success = $false
            error   = $failure.GetType().FullName
        })
    }
    finally {
        $udp.Close()
    }
}

try {
    $service = Get-CimInstance Win32_Service -Filter "Name='W32Time'" -ErrorAction Stop |
        Select-Object -First 1
    if ($service) {
        Emit 'service' ([ordered]@{
            found      = $true
            state      = [string] $service.State
            start_mode = [string] $service.StartMode
        })
    }
    else {
        Emit 'service' ([ordered]@{ found = $false })
    }

    $parameters = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
    $type = if ($parameters) { [string] $parameters.Type } else { '' }
    $raw = if ($parameters) { [string] $parameters.NtpServer } else { '' }
    $servers = @($raw.Split(' ') | Where-Object { $_.Trim() } | ForEach-Object { ($_ -split ',')[0].Trim() } | Where-Object { $_ })
    Emit 'config' ([ordered]@{ type = $type; servers = $servers })

    foreach ($server in $servers) {
        $addresses = @()
        try {
            $addresses = @([System.Net.Dns]::GetHostAddresses($server) | ForEach-Object { $_.IPAddressToString })
        }
        catch {
            Emit 'peer' ([ordered]@{
                server  = $server
                address = $null
                private = $false
                skipped = $false
                success = $false
                error   = $_.Exception.GetType().FullName
            })
            continue
        }
        $private = @($addresses | Where-Object { Test-PrivateAddress $_ })
        if ($private.Count -eq 0) {
            Emit 'peer' ([ordered]@{
                server  = $server
                address = ($addresses | Select-Object -First 1)
                private = $false
                skipped = $true
            })
            continue
        }
        Measure-Peer $server $private[0]
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'time'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
