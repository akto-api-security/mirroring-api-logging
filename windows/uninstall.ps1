#Requires -RunAsAdministrator
<#
.SYNOPSIS
Removes the Akto traffic mirroring service. Logs and the collector id in ProgramData are kept
unless -Purge is passed.

.EXAMPLE
.\uninstall.ps1

.EXAMPLE
.\uninstall.ps1 -Purge
#>
param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

$ServiceName = "AktoTrafficMirroring"
$FirewallRule = "Akto Traffic Mirroring"
$InstallDir = Join-Path $env:ProgramFiles "Akto\TrafficMirroring"
$DataDir = Join-Path $env:ProgramData "Akto"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Write-Host "Stopping $ServiceName"
        Stop-Service -Name $ServiceName -Force
    }
    Write-Host "Deleting service $ServiceName"
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete $ServiceName failed with exit code $LASTEXITCODE"
    }
    for ($i = 0; $i -lt 20 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 500
    }
} else {
    Write-Host "Service $ServiceName is not installed"
}

Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule

if (Test-Path $InstallDir) {
    Write-Host "Removing $InstallDir"
    # the process can take a moment to exit after the service stops
    for ($i = 0; $i -lt 10; $i++) {
        try {
            Remove-Item -Recurse -Force $InstallDir
            break
        } catch {
            if ($i -eq 9) { throw }
            Start-Sleep -Seconds 1
        }
    }
    $parent = Split-Path $InstallDir -Parent
    if ((Test-Path $parent) -and -not (Get-ChildItem $parent)) {
        Remove-Item $parent
    }
}

if ($Purge) {
    if (Test-Path $DataDir) {
        Write-Host "Removing $DataDir"
        Remove-Item -Recurse -Force $DataDir
    }
} elseif (Test-Path $DataDir) {
    Write-Host "Kept logs and collector id in $DataDir (use -Purge to remove them)"
}

Write-Host "Uninstalled"
