<#
    probe_network.ps1 - Erreichbarkeit der lokalen Netzinfrastruktur.

    Gemessen wird ausschliesslich gegen Adressen, die dieses Skript selbst aus
    der IP-Konfiguration des Rechners liest: DNS-Server, Standardgateway,
    DHCP-Server. Es nimmt KEINE Zieladresse von aussen entgegen. Das ist die
    Stelle, an der die Zusage "nur lokales Netz" technisch verankert ist und
    nicht bloss in der Dokumentation steht - ein Aufrufer kann diese Sonde nicht
    dazu bringen, irgendetwas im Internet anzusprechen.

    Zusaetzlich wird jede gefundene Adresse gegen die privaten Bereiche
    geprueft. Wer 8.8.8.8 als DNS-Server eingetragen hat, bekommt dafuer keine
    Messung, sondern den Vermerk "oeffentliche Adresse, uebersprungen".

    Ping ueber System.Net.NetworkInformation.Ping statt ueber Test-Connection:
    Test-Connection liefert in PowerShell 5.1 ein Win32_PingStatus mit dem Feld
    ResponseTime und ab PowerShell 7 ein PingStatus mit dem Feld Latency. Die
    .NET-Klasse ist in beiden Faellen dieselbe.

    Alles nur lesend. Keine Zustandsaenderung, kein Dauertest, keine Last.
#>
[CmdletBinding()]
param(
    # '|'-getrennt statt [string[]]: Ueber -File kaeme "dns,gateway" sonst als
    # EIN Element an, und -contains 'dns' waere still falsch.
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
    # Sprachneutral und ohne Namensaufloesung: es wird nur die Adresse geprueft.
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
    if (($first -band 0xFE) -eq 0xFC) { return $true }   # fc00::/7, Unique Local
    return $false
}

function Measure-Target([string] $RoleName, [string] $Address, [string] $Adapter) {
    $key = "$RoleName|$Address"
    if ($script:Seen.ContainsKey($key)) { return }
    $script:Seen[$key] = $true

    if (-not (Test-PrivateAddress $Address)) {
        Emit 'ziel' ([ordered]@{
            rolle        = $RoleName
            adresse      = $Address
            adapter      = $Adapter
            privat       = $false
            uebersprungen = $true
            grund        = 'Adresse liegt ausserhalb der privaten Bereiche; diese Sonde misst nur im lokalen Netz.'
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
                    # IPStatus ist ein Enum-Name, kein uebersetzter Text.
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

    Emit 'ziel' ([ordered]@{
        rolle         = $RoleName
        adresse       = $Address
        adapter       = $Adapter
        privat        = $true
        uebersprungen = $false
        gesendet      = $sent
        empfangen     = $received
        schnitt_ms    = $avg
        max_ms        = $max
        fehler        = $lastError
    })
}

function Measure-DnsQuery([string] $Server, [string] $Name) {
    $start = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false; $fehler = $null; $antwort = $null
    try {
        # Abgefragt wird ausschliesslich der eigene Rechnername. Damit verlaesst
        # kein fremder Name das Haus, und die Frage ist trotzdem die richtige:
        # antwortet der Server-DIENST, nicht nur der Server-HOST auf ICMP.
        $result = Resolve-DnsName -Name $Name -Server $Server -DnsOnly -NoHostsFile `
            -QuickTimeout -ErrorAction Stop
        $ok = $true
        $first = $result | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($first) { $antwort = [string] $first.IPAddress }
    }
    catch {
        $fehler = $_.Exception.GetType().FullName
    }
    $start.Stop()

    Emit 'dnsabfrage' ([ordered]@{
        server    = $Server
        name      = $Name
        erfolg    = $ok
        antwort   = $antwort
        dauer_ms  = [math]::Round($start.Elapsed.TotalMilliseconds, 0)
        fehler    = $fehler
    })
}

try {
    $configs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = true' -ErrorAction Stop)

    foreach ($cfg in $configs) {
        Emit 'adapter' ([ordered]@{
            beschreibung = $cfg.Description
            index        = $cfg.InterfaceIndex
            adressen     = @($cfg.IPAddress)
            dhcp_aktiv   = [bool] $cfg.DHCPEnabled
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
            Emit 'leer' ([ordered]@{ rolle = 'gateway'; grund = 'Kein Standardgateway eingetragen.' })
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
            Emit 'leer' ([ordered]@{ rolle = 'dhcp'; grund = 'Keine Schnittstelle bezieht ihre Adresse per DHCP.' })
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
            Emit 'leer' ([ordered]@{ rolle = 'dns'; grund = 'Kein DNS-Server eingetragen.' })
        }
        elseif (-not $NoDnsQuery) {
            $eigenerName = $env:COMPUTERNAME
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                foreach ($server in $servers) {
                    if (Test-PrivateAddress $server) { Measure-DnsQuery $server $eigenerName }
                }
            }
            else {
                Emit 'hinweis' ([ordered]@{
                    rolle = 'dns'
                    text  = 'Resolve-DnsName ist auf diesem System nicht verfuegbar; gemessen wurde nur ICMP.'
                })
            }
        }
    }
}
catch {
    $script:Exception = $_.Exception.GetType().FullName
}

$status = [ordered]@{ probe = 'netz'; records = $script:Emitted; exception = $script:Exception }
Write-Output (([ordered]@{ __status = $status }) | ConvertTo-Json -Compress -Depth 4)
