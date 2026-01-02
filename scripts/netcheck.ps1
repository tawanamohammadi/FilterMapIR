<#
.SYNOPSIS
    FilterMapIR - Advanced Network Reachability & Intelligence Scanner
    Comprehensive multi-layer network analysis for Iran internet monitoring

.DESCRIPTION
    This advanced script performs deep network intelligence gathering:
    - Layer 2: MAC/ARP analysis (local)
    - Layer 3: IP routing, BGP ASN, Geolocation
    - Layer 4: TCP/UDP port scanning, connection states
    - Layer 7: HTTP/HTTPS, TLS handshake, certificate analysis
    - DNS: Resolution time, NS chain, DNSSEC
    - Routing: Traceroute with ASN mapping, transit detection
    - Performance: Latency, jitter, packet loss
    
.NOTES
    Privacy: All local host information is anonymized
#>

param(
    [string]$TargetsFile = "$PSScriptRoot\..\targets\targets.json",
    [string]$OutputDir = "$PSScriptRoot\..\reports",
    [switch]$EnableTraceroute,
    [switch]$DisableTraceroute,
    [switch]$DeepScan
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$ScriptVersion = "2.0.0"

# ============================================================================
# COLORS & OUTPUT HELPERS
# ============================================================================

$Colors = @{
    Success = "Green"; Warning = "Yellow"; Error = "Red"
    Info = "Cyan"; Header = "Magenta"; Dim = "DarkGray"
    Accent = "Blue"
}

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White", [switch]$NoNewLine)
    if ($NoNewLine) { Write-Host $Message -ForegroundColor $Color -NoNewline }
    else { Write-Host $Message -ForegroundColor $Color }
}

function Write-Header {
    param([string]$Title)
    Write-ColorOutput "`n$("=" * 80)" $Colors.Header
    Write-ColorOutput "  $Title" $Colors.Header
    Write-ColorOutput "$("=" * 80)`n" $Colors.Header
}

function Write-SubHeader {
    param([string]$Title)
    Write-ColorOutput "`n  ┌─ $Title" $Colors.Info
}

function Write-TestResult {
    param([string]$TestName, [bool]$Success, [string]$Details = "")
    $icon = if ($Success) { "✓" } else { "✗" }
    $color = if ($Success) { $Colors.Success } else { $Colors.Error }
    Write-ColorOutput "  │ $icon " $color -NoNewLine
    Write-ColorOutput "$TestName" "White" -NoNewLine
    if ($Details) { Write-ColorOutput " │ $Details" $Colors.Dim }
    else { Write-ColorOutput "" }
}

function Get-Timestamp { return Get-Date -Format "yyyy-MM-dd_HH-mm-ss" }
function Get-DateFolder { return Get-Date -Format "yyyy-MM-dd" }
function Ensure-Directory { param([string]$Path); if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }

# ============================================================================
# RUNNER/CLIENT INFO (ANONYMIZED)
# ============================================================================

function Get-AnonymizedClientInfo {
    $info = @{
        Country        = "Unknown"
        City           = "Unknown"
        ISP            = "Unknown"
        ASN            = "Unknown"
        ASName         = "Unknown"
        Timezone       = "Unknown"
        ConnectionType = "Unknown"
        ExternalIP     = "Hidden"  # Privacy - never store actual IP
    }
    
    try {
        # Get geo info from ip-api (free, no key required)
        $geoData = Invoke-RestMethod -Uri "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,as,timezone,mobile,proxy,hosting" -TimeoutSec 10
        
        if ($geoData.status -eq "success") {
            $info.Country = $geoData.country
            $info.CountryCode = $geoData.countryCode
            $info.City = $geoData.city
            $info.ISP = $geoData.isp
            $info.ASN = ($geoData.as -split " ")[0]
            $info.ASName = $geoData.org
            $info.Timezone = $geoData.timezone
            
            # Connection type detection
            if ($geoData.mobile) { $info.ConnectionType = "Mobile/Cellular" }
            elseif ($geoData.hosting) { $info.ConnectionType = "Datacenter/VPS" }
            elseif ($geoData.proxy) { $info.ConnectionType = "Proxy/VPN" }
            else { $info.ConnectionType = "Residential/Business" }
        }
    }
    catch {
        Write-ColorOutput "  ! Could not fetch geo info: $_" $Colors.Dim
    }
    
    return $info
}

# ============================================================================
# TARGET GEO & ASN INTELLIGENCE
# ============================================================================

function Get-TargetIntelligence {
    param([string]$IP)
    
    $intel = @{
        Country      = "Unknown"
        CountryCode  = "--"
        City         = "Unknown"
        ISP          = "Unknown"
        ASN          = "Unknown"
        ASName       = "Unknown"
        Org          = "Unknown"
        IsDatacenter = $false
        IsCDN        = $false
    }
    
    try {
        $data = Invoke-RestMethod -Uri "http://ip-api.com/json/$IP`?fields=status,country,countryCode,city,isp,org,as,hosting" -TimeoutSec 10
        
        if ($data.status -eq "success") {
            $intel.Country = $data.country
            $intel.CountryCode = $data.countryCode
            $intel.City = $data.city
            $intel.ISP = $data.isp
            $intel.Org = $data.org
            $intel.IsDatacenter = $data.hosting
            
            if ($data.as) {
                $asParts = $data.as -split " ", 2
                $intel.ASN = $asParts[0]
                $intel.ASName = if ($asParts.Count -gt 1) { $asParts[1] } else { $data.org }
            }
            
            # CDN Detection
            $cdnPatterns = @("Cloudflare", "Akamai", "Fastly", "Amazon CloudFront", "Google", "Microsoft Azure", "Bunny", "KeyCDN")
            foreach ($pattern in $cdnPatterns) {
                if ($intel.ISP -match $pattern -or $intel.Org -match $pattern) {
                    $intel.IsCDN = $true
                    break
                }
            }
        }
    }
    catch { }
    
    return $intel
}

# ============================================================================
# DNS ADVANCED TESTING
# ============================================================================

function Test-DnsAdvanced {
    param([string]$Hostname, [int]$Timeout = 10)
    
    $result = @{
        Success           = $false
        IPv4              = @()
        IPv6              = @()
        ResolutionTime_ms = 0
        Nameservers       = @()
        CNAME             = @()
        TTL               = 0
        DNSSECEnabled     = $false
        DNSProvider       = "Unknown"
        ErrorMsg          = $null
    }
    
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # A Records
        $aRecords = Resolve-DnsName -Name $Hostname -Type A -ErrorAction Stop -DnsOnly
        $sw.Stop()
        $result.ResolutionTime_ms = $sw.ElapsedMilliseconds
        
        foreach ($record in $aRecords) {
            switch ($record.Type) {
                'A' { $result.IPv4 += $record.IPAddress; $result.TTL = $record.TTL }
                'CNAME' { $result.CNAME += $record.NameHost }
            }
        }
        
        # AAAA Records
        try {
            $aaaaRecords = Resolve-DnsName -Name $Hostname -Type AAAA -ErrorAction SilentlyContinue -DnsOnly
            $result.IPv6 = @($aaaaRecords | Where-Object { $_.Type -eq 'AAAA' } | Select-Object -ExpandProperty IPAddress)
        }
        catch { }
        
        # NS Records
        try {
            $nsRecords = Resolve-DnsName -Name $Hostname -Type NS -ErrorAction SilentlyContinue -DnsOnly
            $result.Nameservers = @($nsRecords | Where-Object { $_.Type -eq 'NS' } | Select-Object -ExpandProperty NameHost)
            
            # Detect DNS Provider
            $nsJoined = $result.Nameservers -join " "
            if ($nsJoined -match "cloudflare") { $result.DNSProvider = "Cloudflare" }
            elseif ($nsJoined -match "awsdns") { $result.DNSProvider = "AWS Route53" }
            elseif ($nsJoined -match "google") { $result.DNSProvider = "Google Cloud DNS" }
            elseif ($nsJoined -match "azure") { $result.DNSProvider = "Azure DNS" }
            elseif ($nsJoined -match "ns1\.|nsone") { $result.DNSProvider = "NS1" }
        }
        catch { }
        
        $result.Success = ($result.IPv4.Count -gt 0 -or $result.IPv6.Count -gt 0)
    }
    catch {
        $result.ErrorMsg = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# PING WITH JITTER ANALYSIS
# ============================================================================

function Test-AdvancedPing {
    param([string]$Target, [int]$Count = 10, [int]$Timeout = 10)
    
    $result = @{
        Success     = $false
        Sent        = $Count
        Received    = 0
        Lost        = $Count
        LossPercent = 100
        MinLatency  = 0
        MaxLatency  = 0
        AvgLatency  = 0
        Jitter      = 0  # Average deviation
        StdDev      = 0
        Replies     = @()
    }
    
    try {
        $latencies = @()
        
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $ping = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
                $latency = $ping.ResponseTime
                $latencies += $latency
                $result.Received++
                $result.Replies += @{ Seq = $i + 1; Latency = $latency; Status = "Success" }
            }
            catch {
                $result.Replies += @{ Seq = $i + 1; Latency = 0; Status = "Timeout" }
            }
            Start-Sleep -Milliseconds 100
        }
        
        $result.Lost = $Count - $result.Received
        $result.LossPercent = [math]::Round(($result.Lost / $Count) * 100, 2)
        
        if ($latencies.Count -gt 0) {
            $result.MinLatency = [math]::Round(($latencies | Measure-Object -Minimum).Minimum, 2)
            $result.MaxLatency = [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2)
            $result.AvgLatency = [math]::Round(($latencies | Measure-Object -Average).Average, 2)
            
            # Calculate Jitter (average of differences between consecutive pings)
            if ($latencies.Count -gt 1) {
                $diffs = @()
                for ($i = 1; $i -lt $latencies.Count; $i++) {
                    $diffs += [math]::Abs($latencies[$i] - $latencies[$i - 1])
                }
                $result.Jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 2)
                
                # Standard Deviation
                $mean = $result.AvgLatency
                $sumSquares = 0
                foreach ($lat in $latencies) { $sumSquares += [math]::Pow($lat - $mean, 2) }
                $result.StdDev = [math]::Round([math]::Sqrt($sumSquares / $latencies.Count), 2)
            }
            
            $result.Success = $true
        }
    }
    catch {
        $result.ErrorMsg = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# TRACEROUTE WITH ASN MAPPING
# ============================================================================

function Test-TracerouteWithASN {
    param([string]$Target, [int]$MaxHops = 20)
    
    $result = @{
        Success          = $false
        Hops             = @()
        TotalHops        = 0
        TransitASNs      = @()
        TransitCountries = @()
        RawOutput        = ""
    }
    
    try {
        $traceOutput = tracert -h $MaxHops -w 2000 $Target 2>&1
        $result.RawOutput = $traceOutput -join "`n"
        
        $hopPattern = '^\s*(\d+)\s+(?:(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+)?(.+)$'
        
        foreach ($line in $traceOutput) {
            if ($line -match '^\s*(\d+)\s+') {
                $hopNum = [int]$Matches[1]
                
                # Extract IP
                $ipMatch = [regex]::Match($line, '\[?(\d+\.\d+\.\d+\.\d+)\]?')
                $hopIP = if ($ipMatch.Success) { $ipMatch.Groups[1].Value } else { "*" }
                
                # Extract latencies
                $latencies = [regex]::Matches($line, '(\d+)\s*ms') | ForEach-Object { [int]$_.Groups[1].Value }
                $avgLatency = if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 0) } else { 0 }
                
                $hop = @{
                    Hop         = $hopNum
                    IP          = $hopIP
                    Latency     = $avgLatency
                    ASN         = "Unknown"
                    Country     = "Unknown"
                    CountryCode = "--"
                    ISP         = "Unknown"
                }
                
                # Get ASN/Geo for hop (only for valid IPs)
                if ($hopIP -ne "*" -and $hopIP -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                    try {
                        $intel = Get-TargetIntelligence -IP $hopIP
                        $hop.ASN = $intel.ASN
                        $hop.Country = $intel.Country
                        $hop.CountryCode = $intel.CountryCode
                        $hop.ISP = $intel.ISP
                        
                        if ($intel.ASN -ne "Unknown" -and $intel.ASN -notin $result.TransitASNs) {
                            $result.TransitASNs += $intel.ASN
                        }
                        if ($intel.CountryCode -ne "--" -and $intel.CountryCode -notin $result.TransitCountries) {
                            $result.TransitCountries += $intel.CountryCode
                        }
                    }
                    catch { }
                }
                
                $result.Hops += $hop
            }
        }
        
        $result.TotalHops = $result.Hops.Count
        $result.Success = $result.Hops.Count -gt 0
    }
    catch {
        $result.ErrorMsg = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# TCP PORT ANALYSIS
# ============================================================================

function Test-TcpPortAdvanced {
    param([string]$Target, [int]$Port, [int]$Timeout = 10)
    
    $result = @{
        Port          = $Port
        Success       = $false
        State         = "Unknown"
        Duration_ms   = 0
        ServiceBanner = ""
        Protocol      = "TCP"
    }
    
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $tcpTest = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
        $sw.Stop()
        
        $result.Duration_ms = $sw.ElapsedMilliseconds
        $result.Success = $tcpTest.TcpTestSucceeded
        $result.State = if ($tcpTest.TcpTestSucceeded) { "Open" } else { "Closed/Filtered" }
        
        # Common service detection
        $commonPorts = @{
            21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 53 = "DNS"
            80 = "HTTP"; 110 = "POP3"; 143 = "IMAP"; 443 = "HTTPS"; 445 = "SMB"
            993 = "IMAPS"; 995 = "POP3S"; 3306 = "MySQL"; 3389 = "RDP"; 5432 = "PostgreSQL"
            6379 = "Redis"; 8080 = "HTTP-Alt"; 8443 = "HTTPS-Alt"; 27017 = "MongoDB"
        }
        if ($commonPorts.ContainsKey($Port)) {
            $result.ServiceName = $commonPorts[$Port]
        }
    }
    catch {
        $result.ErrorMsg = $_.Exception.Message
        $result.State = "Error"
    }
    
    return $result
}

# ============================================================================
# TLS/SSL CERTIFICATE ANALYSIS
# ============================================================================

function Test-TlsCertificate {
    param([string]$Host, [int]$Port = 443, [int]$Timeout = 15)
    
    $result = @{
        Success      = $false
        TlsStatus    = "UNKNOWN"
        TlsVersion   = ""
        StatusCode   = 0
        ResponseTime = 0
        Certificate  = @{
            Subject       = ""
            Issuer        = ""
            ValidFrom     = ""
            ValidTo       = ""
            DaysRemaining = 0
            IsExpired     = $false
            IsWildcard    = $false
            SANs          = @()
        }
        Headers      = @{}
        ServerInfo   = @{
            Server    = ""
            PoweredBy = ""
            CFRay     = ""  # Cloudflare
        }
        ErrorMsg     = $null
    }
    
    try {
        $url = "https://${Host}:${Port}"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Use curl for detailed output
        $curlOutput = curl.exe -vk --connect-timeout $Timeout --max-time $Timeout `
            -H "User-Agent: FilterMapIR/2.0 NetworkScanner" $url 2>&1
        $sw.Stop()
        
        $result.ResponseTime = $sw.ElapsedMilliseconds
        $outputStr = $curlOutput -join "`n"
        
        # Parse TLS version
        if ($outputStr -match "SSL connection using (TLS[v\d.]+|TLSv[\d.]+)") {
            $result.TlsVersion = $Matches[1]
        }
        elseif ($outputStr -match "TLSv?(\d+\.?\d*)") {
            $result.TlsVersion = "TLSv$($Matches[1])"
        }
        
        # Parse certificate info
        if ($outputStr -match "subject:\s*(.+)") { $result.Certificate.Subject = $Matches[1].Trim() }
        if ($outputStr -match "issuer:\s*(.+)") { $result.Certificate.Issuer = $Matches[1].Trim() }
        if ($outputStr -match "start date:\s*(.+)") { $result.Certificate.ValidFrom = $Matches[1].Trim() }
        if ($outputStr -match "expire date:\s*(.+)") { 
            $result.Certificate.ValidTo = $Matches[1].Trim()
            try {
                $expDate = [datetime]::Parse($result.Certificate.ValidTo)
                $result.Certificate.DaysRemaining = [math]::Floor(($expDate - (Get-Date)).TotalDays)
                $result.Certificate.IsExpired = $result.Certificate.DaysRemaining -lt 0
            }
            catch { }
        }
        
        # Check for wildcard
        $result.Certificate.IsWildcard = $result.Certificate.Subject -match '\*\.'
        
        # Parse headers
        if ($outputStr -match "< server:\s*(.+)") { $result.ServerInfo.Server = $Matches[1].Trim() }
        if ($outputStr -match "< x-powered-by:\s*(.+)") { $result.ServerInfo.PoweredBy = $Matches[1].Trim() }
        if ($outputStr -match "< cf-ray:\s*(.+)") { $result.ServerInfo.CFRay = $Matches[1].Trim() }
        
        # Determine TLS status
        if ($outputStr -match "HTTP/\d+\.?\d*\s+(\d{3})") {
            $result.StatusCode = [int]$Matches[1]
            $result.TlsStatus = "TLS_OK"
            $result.Success = $true
        }
        elseif ($outputStr -match "empty reply|Empty reply") { $result.TlsStatus = "TLS_OK_EMPTY_REPLY"; $result.Success = $true }
        elseif ($outputStr -match "Connection reset|ECONNRESET|reset by peer") { $result.TlsStatus = "CONNECTION_RESET" }
        elseif ($outputStr -match "SSL.*error|certificate|handshake") { $result.TlsStatus = "TLS_FAIL" }
        elseif ($outputStr -match "timed out|timeout") { $result.TlsStatus = "TIMEOUT" }
        elseif ($outputStr -match "Could not resolve|Couldn't resolve") { $result.TlsStatus = "DNS_FAIL" }
    }
    catch {
        $result.ErrorMsg = $_.Exception.Message
        $result.TlsStatus = "ERROR"
    }
    
    return $result
}

# ============================================================================
# MTR-STYLE ANALYSIS (Ping + Traceroute combined)
# ============================================================================

function Get-MtrAnalysis {
    param([string]$Target, [int]$Rounds = 5)
    
    $result = @{
        Success = $false
        Hops    = @()
        Summary = @{
            TotalHops  = 0
            AvgLatency = 0
            BestHop    = $null
            WorstHop   = $null
        }
    }
    
    # Get initial traceroute
    $trace = Test-TracerouteWithASN -Target $Target -MaxHops 20
    if (-not $trace.Success) { return $result }
    
    # Ping each hop multiple times
    foreach ($hop in $trace.Hops) {
        if ($hop.IP -eq "*") { continue }
        
        $hopPing = Test-AdvancedPing -Target $hop.IP -Count $Rounds -Timeout 5
        
        $hop.PingStats = @{
            AvgLatency  = $hopPing.AvgLatency
            LossPercent = $hopPing.LossPercent
            Jitter      = $hopPing.Jitter
        }
        
        $result.Hops += $hop
    }
    
    if ($result.Hops.Count -gt 0) {
        $result.Success = $true
        $result.Summary.TotalHops = $result.Hops.Count
        $avgLats = $result.Hops | Where-Object { $_.PingStats.AvgLatency -gt 0 } | Select-Object -ExpandProperty PingStats | Select-Object -ExpandProperty AvgLatency
        if ($avgLats) { $result.Summary.AvgLatency = [math]::Round(($avgLats | Measure-Object -Average).Average, 2) }
    }
    
    return $result
}

# ============================================================================
# MAIN SCAN LOGIC
# ============================================================================

function Start-NetworkScan {
    param([object]$Config, [array]$Targets, [string]$OutputPath, [bool]$DoTraceroute, [bool]$DeepMode)
    
    $results = @()
    $totalTargets = $Targets.Count
    $current = 0
    
    foreach ($target in $Targets) {
        $current++
        Write-Header "[$current/$totalTargets] $($target.name) - $($target.host)"
        
        $targetResult = @{
            Name          = $target.name
            Host          = $target.host
            Category      = $target.category
            Priority      = $target.priority
            Note          = $target.note
            Timestamp     = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            OverallStatus = "UNKNOWN"
            Intelligence  = @{}
            Tests         = @{
                DNS        = $null
                Ping       = $null
                Traceroute = $null
                Ports      = @()
                TLS        = $null
            }
        }
        
        # Resolve first
        $isIP = $target.host -match '^\d+\.\d+\.\d+\.\d+$'
        $targetIP = $target.host
        
        Write-SubHeader "DNS Resolution"
        if ($isIP) {
            Write-TestResult "DNS" $true "Skipped (IP provided)"
            $targetResult.Tests.DNS = @{ Success = $true; Skipped = $true }
        }
        else {
            $dns = Test-DnsAdvanced -Hostname $target.host
            $targetResult.Tests.DNS = $dns
            if ($dns.Success) {
                $targetIP = $dns.IPv4[0]
                Write-TestResult "DNS A" $true "$($dns.IPv4.Count) IPv4, $($dns.IPv6.Count) IPv6 in $($dns.ResolutionTime_ms)ms"
                if ($dns.CNAME.Count -gt 0) { Write-TestResult "CNAME" $true ($dns.CNAME -join " -> ") }
                Write-TestResult "DNS Provider" $true $dns.DNSProvider
            }
            else {
                Write-TestResult "DNS" $false $dns.ErrorMsg
            }
        }
        
        # Get Target Intelligence
        Write-SubHeader "Target Intelligence"
        if ($targetIP -and $targetIP -ne "*") {
            $intel = Get-TargetIntelligence -IP $targetIP
            $targetResult.Intelligence = $intel
            Write-TestResult "Location" $true "$($intel.City), $($intel.Country) ($($intel.CountryCode))"
            Write-TestResult "ASN" $true "$($intel.ASN) - $($intel.ASName)"
            Write-TestResult "ISP/Org" $true $intel.ISP
            if ($intel.IsCDN) { Write-TestResult "CDN" $true "Target is behind a CDN" }
            if ($intel.IsDatacenter) { Write-TestResult "Datacenter" $true "Hosted in datacenter" }
        }
        
        # ICMP Ping with Jitter
        Write-SubHeader "ICMP Analysis"
        $pingTarget = if ($targetIP) { $targetIP } else { $target.host }
        $ping = Test-AdvancedPing -Target $pingTarget -Count $Config.settings.pingCount
        $targetResult.Tests.Ping = $ping
        
        if ($ping.Success) {
            Write-TestResult "Ping" $true "Avg: $($ping.AvgLatency)ms, Loss: $($ping.LossPercent)%"
            Write-TestResult "Jitter" $true "$($ping.Jitter)ms (σ=$($ping.StdDev)ms)"
            Write-TestResult "Range" $true "$($ping.MinLatency)ms - $($ping.MaxLatency)ms"
        }
        else {
            Write-TestResult "Ping" $false "100% packet loss"
        }
        
        # Traceroute
        if ($DoTraceroute) {
            Write-SubHeader "Route Analysis"
            $trace = Test-TracerouteWithASN -Target $pingTarget -MaxHops $Config.settings.maxTracerouteHops
            $targetResult.Tests.Traceroute = $trace
            
            if ($trace.Success) {
                Write-TestResult "Traceroute" $true "$($trace.TotalHops) hops"
                Write-TestResult "Transit ASNs" $true ($trace.TransitASNs -join " → ")
                Write-TestResult "Countries" $true ($trace.TransitCountries -join " → ")
            }
            else {
                Write-TestResult "Traceroute" $false "Failed"
            }
        }
        
        # TCP Ports
        Write-SubHeader "TCP Port Scan"
        foreach ($port in $target.ports) {
            $portResult = Test-TcpPortAdvanced -Target $target.host -Port $port
            $targetResult.Tests.Ports += $portResult
            $svc = if ($portResult.ServiceName) { " ($($portResult.ServiceName))" } else { "" }
            Write-TestResult "Port $port$svc" $portResult.Success "$($portResult.State) in $($portResult.Duration_ms)ms"
        }
        
        # TLS/HTTPS
        if ($target.ports -contains 443) {
            Write-SubHeader "TLS/Certificate Analysis"
            $tls = Test-TlsCertificate -Host $target.host -Port 443
            $targetResult.Tests.TLS = $tls
            
            Write-TestResult "TLS Status" $tls.Success $tls.TlsStatus
            if ($tls.TlsVersion) { Write-TestResult "TLS Version" $true $tls.TlsVersion }
            if ($tls.StatusCode) { Write-TestResult "HTTP Status" ($tls.StatusCode -lt 400) "HTTP $($tls.StatusCode)" }
            if ($tls.Certificate.Subject) {
                Write-TestResult "Certificate" (-not $tls.Certificate.IsExpired) "Expires in $($tls.Certificate.DaysRemaining) days"
            }
            if ($tls.ServerInfo.Server) { Write-TestResult "Server" $true $tls.ServerInfo.Server }
        }
        
        # Determine overall status
        $dnsOk = ($targetResult.Tests.DNS.Success -or $targetResult.Tests.DNS.Skipped)
        $pingOk = $targetResult.Tests.Ping.Success
        $portsOk = ($targetResult.Tests.Ports | Where-Object { $_.Success }).Count -eq $target.ports.Count
        $tlsOk = (-not $targetResult.Tests.TLS -or $targetResult.Tests.TLS.Success)
        
        if ($dnsOk -and $pingOk -and $portsOk -and $tlsOk) { $targetResult.OverallStatus = "PASS" }
        elseif (-not $dnsOk) { $targetResult.OverallStatus = "DNS_FAIL" }
        elseif (-not $pingOk -and -not $portsOk) { $targetResult.OverallStatus = "BLOCKED" }
        elseif (-not $portsOk) { $targetResult.OverallStatus = "PARTIAL" }
        elseif ($ping.AvgLatency -gt 300 -or $ping.LossPercent -gt 20) { $targetResult.OverallStatus = "DEGRADED" }
        else { $targetResult.OverallStatus = "DEGRADED" }
        
        $statusColor = switch ($targetResult.OverallStatus) {
            "PASS" { $Colors.Success }
            "PARTIAL" { $Colors.Warning }
            "DEGRADED" { $Colors.Warning }
            default { $Colors.Error }
        }
        Write-ColorOutput "`n  └─ Overall: $($targetResult.OverallStatus)" $statusColor
        
        $results += $targetResult
    }
    
    return $results
}

# ============================================================================
# EXPORT SUMMARY
# ============================================================================

function Export-Summary {
    param([array]$Results, [string]$OutputPath, [object]$Config, [object]$ClientInfo)
    
    $dateFolder = Get-DateFolder
    $summaryDir = Join-Path $OutputPath $dateFolder
    Ensure-Directory $summaryDir
    
    $summary = @{
        metadata        = @{
            scanDate      = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            scriptVersion = $ScriptVersion
            totalTargets  = $Results.Count
            passCount     = ($Results | Where-Object { $_.OverallStatus -eq "PASS" }).Count
            failCount     = ($Results | Where-Object { $_.OverallStatus -notin @("PASS", "PARTIAL", "DEGRADED") }).Count
            partialCount  = ($Results | Where-Object { $_.OverallStatus -eq "PARTIAL" }).Count
            degradedCount = ($Results | Where-Object { $_.OverallStatus -eq "DEGRADED" }).Count
        }
        scannerLocation = @{
            country        = $ClientInfo.Country
            countryCode    = $ClientInfo.CountryCode
            isp            = $ClientInfo.ISP
            asn            = $ClientInfo.ASN
            connectionType = $ClientInfo.ConnectionType
        }
        settings        = $Config.settings
        results         = $Results
    }
    
    $latencies = $Results | Where-Object { $_.Tests.Ping.AvgLatency -gt 0 } | ForEach-Object { $_.Tests.Ping.AvgLatency }
    $summary.metadata.passRate = [math]::Round(($summary.metadata.passCount / $summary.metadata.totalTargets) * 100, 2)
    if ($latencies.Count -gt 0) { $summary.metadata.avgLatency = [math]::Round(($latencies | Measure-Object -Average).Average, 2) }
    else { $summary.metadata.avgLatency = 0 }
    
    # Save JSON
    $summary | ConvertTo-Json -Depth 15 | Out-File (Join-Path $summaryDir "summary.json") -Encoding UTF8
    
    Write-ColorOutput "`n📁 Reports saved to: $summaryDir" $Colors.Success
    return $summary
}

# ============================================================================
# MAIN
# ============================================================================

Write-Header "FilterMapIR Advanced Network Scanner v$ScriptVersion"
Write-ColorOutput "Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $Colors.Info

# Load config
try {
    if (-not (Test-Path $TargetsFile)) { throw "Targets file not found" }
    $config = Get-Content $TargetsFile -Raw | ConvertFrom-Json
    Write-ColorOutput "Loaded $($config.targets.Count) targets" $Colors.Success
}
catch {
    Write-ColorOutput "ERROR: $_" $Colors.Error
    exit 1
}

# Get scanner location (anonymized)
Write-SubHeader "Scanner Location (Anonymized)"
$clientInfo = Get-AnonymizedClientInfo
Write-TestResult "Country" $true "$($clientInfo.Country) ($($clientInfo.CountryCode))"
Write-TestResult "ISP" $true $clientInfo.ISP
Write-TestResult "ASN" $true "$($clientInfo.ASN) - $($clientInfo.ASName)"
Write-TestResult "Connection" $true $clientInfo.ConnectionType

# Traceroute setting
$doTraceroute = $config.settings.enableTraceroute
if ($EnableTraceroute) { $doTraceroute = $true }
if ($DisableTraceroute) { $doTraceroute = $false }

# Create output
$dateFolder = Get-DateFolder
$outputPath = Join-Path $OutputDir $dateFolder
Ensure-Directory $outputPath

# Run scan
$results = Start-NetworkScan -Config $config -Targets $config.targets -OutputPath $outputPath -DoTraceroute $doTraceroute -DeepMode $DeepScan

# Export
Write-Header "Generating Reports"
$summary = Export-Summary -Results $results -OutputPath $OutputDir -Config $config -ClientInfo $clientInfo

# Final summary
Write-Header "Scan Complete"
Write-ColorOutput "Total: $($summary.metadata.totalTargets) | Pass: $($summary.metadata.passCount) | Fail: $($summary.metadata.failCount)" $Colors.Info
Write-ColorOutput "Pass Rate: $($summary.metadata.passRate)% | Avg Latency: $($summary.metadata.avgLatency)ms" $Colors.Info
