param(
    [string]$AgentBaseUrl = "http://127.0.0.1:7777",
    [int]$PollSeconds = 1,
    [int]$MaxPolls = 120,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Url {
    param([string]$Url)
    return $Url.Trim().TrimEnd('/')
}

function Invoke-AgentRequest {
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter(Mandatory)] [string]$Url
    )

    return Invoke-RestMethod -Method $Method -Uri $Url -TimeoutSec 15 -UseBasicParsing
}

function Try-GetField {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)] [string]$Name
    )

    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }
    return $null
}

function To-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Get-Count {
    param($Value)

    if ($null -eq $Value) { return 0 }
    if ($Value -is [string]) { return $Value.Length }
    if ($Value -is [array]) { return $Value.Count }
    if ($Value -is [System.Collections.ICollection]) { return $Value.Count }
    return 1
}

$base = Normalize-Url $AgentBaseUrl

if (-not ($base -match '^https?://')) {
    throw "AgentBaseUrl must start with http:// or https://. Got: $base"
}

$start = Invoke-AgentRequest -Method POST -Url "$base/scan/start"
if (-not (Try-GetField -Object $start -Name 'scan_id')) {
    throw "Scan start response did not include scan_id."
}
$scanId = [string](Try-GetField -Object $start -Name 'scan_id')

Write-Host "Scan started: $scanId"

$scan = $null
$attempt = 0
while ($attempt -lt $MaxPolls) {
    Start-Sleep -Seconds $PollSeconds
    $attempt++
    $scan = Invoke-AgentRequest -Method GET -Url "$base/scan/$scanId"
    if ($null -eq $scan) {
        throw "No response for /scan/$scanId"
    }
    if (Try-GetField -Object $scan -Name 'scan_finished_at') {
        break
    }
}

if (-not (Try-GetField -Object $scan -Name 'scan_finished_at')) {
    throw "Scan did not finish within timeout ($($MaxPolls * $PollSeconds)s). Last seen status: $($scan.scan_finished_at)"
}

$devicesResp = Invoke-AgentRequest -Method GET -Url "$base/devices"
$devices = To-Array (Try-GetField -Object $devicesResp -Name 'devices')

$summary = [ordered]@{
    timestamp_utc            = (Get-Date).ToUniversalTime().ToString('o')
    agent_base_url           = $base
    scan_id                  = $scanId
    total_devices            = $devices.Count
    unknown_count            = 0
    device_type_counts       = @{}
    avg_confidence           = 0.0
    confidence_min           = [double]::NaN
    confidence_max           = [double]::NaN
    avg_signal_count         = 0.0
    sources_seen_counts      = @{}
    protocol_presence_counts = @{
        mdns_devices          = 0
        ssdp_devices          = 0
        netbios_devices       = 0
        tcp_probe_devices     = 0
    }
    feature_presence_counts  = @{
        vendor_present        = 0
        hostname_present      = 0
        ip_present            = 0
        mac_present           = 0
        ports_present         = 0
        protocols_seen_present = 0
    }
    unknown_devices         = @()
}

$confTotal = 0.0
$confMin   = [double]::PositiveInfinity
$confMax   = [double]::NegativeInfinity
$signalTotal = 0

foreach ($d in $devices) {
    $type = [string](Try-GetField -Object $d -Name 'device_type')
    if (-not $summary.device_type_counts.ContainsKey($type)) {
        $summary.device_type_counts[$type] = 0
    }
    $summary.device_type_counts[$type]++

    if ($type -eq 'unknown') {
        $summary.unknown_count++
    }

    $sourcesSeen = To-Array (Try-GetField -Object $d -Name 'sources_seen')
    foreach ($s in $sourcesSeen) {
        $key = [string]$s
        if (-not $summary.sources_seen_counts.ContainsKey($key)) {
            $summary.sources_seen_counts[$key] = 0
        }
        $summary.sources_seen_counts[$key]++
    }

    $ip       = Try-GetField -Object $d -Name 'ip'
    $mac      = Try-GetField -Object $d -Name 'mac'
    $vendor   = Try-GetField -Object $d -Name 'vendor'
    $hostname = Try-GetField -Object $d -Name 'hostname'
    $ports    = To-Array (Try-GetField -Object $d -Name 'ports_open')
    $protocols = Try-GetField -Object $d -Name 'protocols_seen'
    $mdns = @()
    $ssdp = @()
    $netbios = @()
    if ($protocols) {
        $summary.feature_presence_counts.protocols_seen_present++
        $mdns = To-Array (Try-GetField -Object $protocols -Name 'mdns')
        $ssdp = To-Array (Try-GetField -Object $protocols -Name 'ssdp')
        $netbios = To-Array (Try-GetField -Object $protocols -Name 'netbios')
    }

    if ($ip) { $summary.feature_presence_counts.ip_present += 1 }
    if ($mac) { $summary.feature_presence_counts.mac_present += 1 }
    if ($vendor -and $vendor -ne '') { $summary.feature_presence_counts.vendor_present++ }
    if ($hostname -and $hostname -ne '') { $summary.feature_presence_counts.hostname_present++ }
    if ((Get-Count -Value $ports) -gt 0) { $summary.feature_presence_counts.ports_present++ }

    if ((Get-Count -Value $mdns) -gt 0) { $summary.protocol_presence_counts.mdns_devices++ }
    if ((Get-Count -Value $ssdp) -gt 0) { $summary.protocol_presence_counts.ssdp_devices++ }
    if ((Get-Count -Value $netbios) -gt 0) { $summary.protocol_presence_counts.netbios_devices++ }
    if ($sourcesSeen | Where-Object { $_ -eq 'tcp_probe' } | Select-Object -First 1) {
        $summary.protocol_presence_counts.tcp_probe_devices++
    }

    $signalCount = 0
    if ($vendor -and $vendor.Trim()) { $signalCount++ }
    if ($hostname -and $hostname.Trim()) { $signalCount++ }
    if ((Get-Count -Value $mdns) -gt 0) { $signalCount++ }
    if ((Get-Count -Value $ssdp) -gt 0) { $signalCount++ }
    if ((Get-Count -Value $netbios) -gt 0) { $signalCount++ }
    if ((Get-Count -Value $ports) -gt 0) { $signalCount++ }
    $signalTotal += $signalCount

    $conf = [double](Try-GetField -Object $d -Name 'confidence')
    $confTotal += $conf
    if ($conf -lt $confMin) { $confMin = $conf }
    if ($conf -gt $confMax) { $confMax = $conf }

    if ($type -eq 'unknown') {
        $summary.unknown_devices += [PSCustomObject]@{
            id       = [string](Try-GetField -Object $d -Name 'id')
            ip       = [string]$ip
            mac      = [string]$mac
            vendor   = [string]$vendor
            hostname = [string]$hostname
            confidence = $conf
            sources_seen = $sourcesSeen
            protocols_seen = @{
                mdns    = if ((Get-Count -Value $mdns) -gt 0) { $mdns } else { @() }
                ssdp    = if ((Get-Count -Value $ssdp) -gt 0) { $ssdp } else { @() }
                netbios = if ((Get-Count -Value $netbios) -gt 0) { $netbios } else { @() }
            }
            ports_open = $ports
            classification_reasons = To-Array (Try-GetField -Object $d -Name 'classification_reasons')
            flags = To-Array (Try-GetField -Object $d -Name 'flags')
        }
    }
}

if ($devices.Count -gt 0) {
    $summary.avg_confidence = [math]::Round($confTotal / $devices.Count, 3)
    $summary.confidence_min = if ($confMin -eq [double]::PositiveInfinity) { $null } else { [math]::Round($confMin, 3) }
    $summary.confidence_max = if ($confMax -eq [double]::NegativeInfinity) { $null } else { [math]::Round($confMax, 3) }
    $summary.avg_signal_count = [math]::Round($signalTotal / $devices.Count, 2)
}

$summary.unknown_ratio = if ($devices.Count -gt 0) { [math]::Round($summary.unknown_count / $devices.Count, 3) } else { 0 }

$output = [PSCustomObject]$summary
$json = $output | ConvertTo-Json -Depth 10

Write-Host "`n--- Discovery/Labeling diagnostics ---"
Write-Host "Total devices: $($summary.total_devices)"
Write-Host "Unknown: $($summary.unknown_count) (ratio: $([string]::Format('{0:P1}', $summary.unknown_ratio)))"
Write-Host "Avg confidence: $($summary.avg_confidence) (min=$($summary.confidence_min), max=$($summary.confidence_max))"
Write-Host "Signal sources per device avg: $($summary.avg_signal_count)"
Write-Host "Protocol presence: mdns=$($summary.protocol_presence_counts.mdns_devices), ssdp=$($summary.protocol_presence_counts.ssdp_devices), netbios=$($summary.protocol_presence_counts.netbios_devices), tcp_probe=$($summary.protocol_presence_counts.tcp_probe_devices)"
Write-Host "Feature presence: vendor=$($summary.feature_presence_counts.vendor_present), hostname=$($summary.feature_presence_counts.hostname_present), ports=$($summary.feature_presence_counts.ports_present), protocols=$($summary.feature_presence_counts.protocols_seen_present)"

if ($OutputPath) {
    $json | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Saved JSON report to: $OutputPath"
}

$json
