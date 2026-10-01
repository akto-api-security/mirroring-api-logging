#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs the Akto traffic mirroring module as a Windows service. Running it again upgrades or
reconfigures an existing install.

.EXAMPLE
.\install.ps1 -KafkaUrl "10.0.0.10:9092"

.EXAMPLE
.\install.ps1 -KafkaUrl "10.0.0.10:9092" -MongoConn "mongodb://10.0.0.10:27017/admini" -ExtraEnv @{ AKTO_THREAT_ENABLED = "false" }
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$KafkaUrl,
    [string]$MongoConn = "",
    [string]$Interface = "any",
    [int]$BatchSize = 100,
    [int]$BatchTimeSecs = 10,
    [hashtable]$ExtraEnv = @{}
)

$ErrorActionPreference = "Stop"

$ServiceName = "AktoTrafficMirroring"
$DisplayName = "Akto Traffic Mirroring"
$FirewallRule = "Akto Traffic Mirroring"
$ExeName = "mirroring-api-logging.exe"
$InstallDir = Join-Path $env:ProgramFiles "Akto\TrafficMirroring"
$SourceExe = Join-Path $PSScriptRoot $ExeName
$TargetExe = Join-Path $InstallDir $ExeName
$LogFile = Join-Path $env:ProgramData "Akto\logs\mirroring.log"

function Invoke-Sc {
    & sc.exe @args | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $args failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path $SourceExe)) {
    throw "$ExeName not found next to install.ps1"
}

# remove an existing install first, so this script also handles upgrades
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing $ServiceName service..."
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
    }
    Invoke-Sc delete $ServiceName
    for ($i = 0; $i -lt 20 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 500
    }
}

Write-Host "Copying $ExeName to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
# the old process can take a moment to exit after the service stops
for ($i = 0; $i -lt 10; $i++) {
    try {
        Copy-Item -Path $SourceExe -Destination $TargetExe -Force
        break
    } catch {
        if ($i -eq 9) { throw }
        Start-Sleep -Seconds 1
    }
}

Write-Host "Creating service $ServiceName"
New-Service -Name $ServiceName `
    -BinaryPathName "`"$TargetExe`"" `
    -DisplayName $DisplayName `
    -Description "Captures HTTP traffic on this machine and sends it to Akto" `
    -StartupType Automatic | Out-Null

$envVars = [ordered]@{
    "AKTO_KAFKA_BROKER_URL"        = $KafkaUrl
    "AKTO_MONGO_CONN"              = $MongoConn
    "AKTO_TRAFFIC_BATCH_SIZE"      = "$BatchSize"
    "AKTO_TRAFFIC_BATCH_TIME_SECS" = "$BatchTimeSecs"
    "MIRRORING_INTERFACE"          = $Interface
}
foreach ($key in $ExtraEnv.Keys) {
    $envVars[$key] = "$($ExtraEnv[$key])"
}

# a service reads its environment variables from this registry value
$envList = @($envVars.GetEnumerator() | Where-Object { $_.Value -ne "" } | ForEach-Object { "$($_.Key)=$($_.Value)" })
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
    -Name Environment -PropertyType MultiString -Value $envList -Force | Out-Null

# restart on failure, this also covers the hourly restart and the memory limit exit
Invoke-Sc failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000
Invoke-Sc failureflag $ServiceName 1

# raw sockets only receive the inbound packets the firewall lets through to this program
Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Program $TargetExe -Action Allow | Out-Null

Write-Host "Starting service"
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

Get-Service -Name $ServiceName | Format-Table -AutoSize Name, Status, StartType
Write-Host "Environment:"
$envList | ForEach-Object { Write-Host "  $_" }
Write-Host "Logs: $LogFile"
Write-Host "Follow them with: Get-Content -Wait -Tail 50 `"$LogFile`""
