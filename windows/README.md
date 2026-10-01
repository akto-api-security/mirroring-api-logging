# Windows

On Windows the module runs as a native exe installed as a Windows service. Docker can't be used
because Linux containers run inside a separate VM and can't see the host's network adapters.

Capture uses Windows raw sockets (`SIO_RCVALL`), so there is nothing else to install (no Npcap).
The exe opens a raw socket per network adapter and IP version, and feeds the packets into the same
parsing and Kafka code used on Linux.

Requirements: Windows 10 / Server 2016 or newer, 64-bit, and Administrator rights.

Limitations compared to Linux:

- IPv6 capture is implemented but not verified yet. If Windows doesn't deliver IPv6 headers to
  raw sockets, the log says so and only IPv4 is captured.
- Traffic between two programs on the same machine (`localhost`, or the machine's own IP) never
  reaches a real adapter. It was captured on Windows Server in testing, but this may differ
  between Windows versions.
- HTTPS is only readable if TLS is terminated before this machine (same as Linux).

## Build

On macOS or Linux, from the repo root:

```sh
./windows/build.sh
```

This creates `dist/akto-traffic-mirroring-windows-amd64.zip` with:

| File | Purpose |
|---|---|
| `mirroring-api-logging.exe` | The module |
| `install.ps1` | Installs or upgrades the Windows service |
| `uninstall.ps1` | Removes the service |

## Test on a Windows machine

You need an HTTP (not HTTPS) service on the machine to send requests to, for example an IIS site
or any app listening on a port.

### 1. Copy the zip to the machine

Use a file share, or for a cloud VM, RDP folder redirection: in the Windows App / Microsoft Remote
Desktop on macOS, edit the PC, open **Folders**, enable **Redirect folders** and add the `dist`
folder, then reconnect. Then, in an **Administrator** PowerShell:

```powershell
cd $env:USERPROFILE\Desktop
Copy-Item "\\tsclient\dist\akto-traffic-mirroring-windows-amd64.zip" .\akto.zip
Expand-Archive akto.zip -DestinationPath . -Force
cd akto-traffic-mirroring-windows-amd64
Get-ChildItem | Unblock-File
Set-ExecutionPolicy -Scope Process Bypass -Force
```

### 2. Check Kafka is reachable

The Kafka of the mini-runtime has to be reachable from the machine, and it has to advertise an
address the machine can reach (check `KAFKA_ADVERTISED_LISTENERS`). If it advertises `localhost`
or a docker hostname, the first connection works and the following ones fail.

```powershell
Test-NetConnection <mini-runtime-ip> -Port 9092
```

### 3. Capture in the console

```powershell
# raw sockets only see inbound packets the firewall lets through to the exe
New-NetFirewallRule -DisplayName "Akto Traffic Mirroring (test)" -Direction Inbound -Program "$PWD\mirroring-api-logging.exe" -Action Allow

$env:AKTO_KAFKA_BROKER_URL = "<mini-runtime-ip>:9092"
$env:AKTO_TRAFFIC_BATCH_SIZE = "100"
$env:AKTO_TRAFFIC_BATCH_TIME_SECS = "10"
$env:DEBUG_URLS = "/some/path"
cmd /c "mirroring-api-logging.exe > capture.log 2>&1"
```

`DEBUG_URLS` logs each step for requests whose path or host contains the value. `cmd /c` is used
for the redirect because Windows PowerShell 5.1 mangles a program's stderr when redirecting it,
and the module logs to stderr.

Send requests to the HTTP service, from another machine and from the machine itself.
`--noproxy` skips any system proxy, `-6` forces IPv6:

```powershell
curl.exe --noproxy "*" "http://<machine-ip>:<port>/some/path"
curl.exe --noproxy "*" "http://127.0.0.1:<port>/some/path"
curl.exe --noproxy "*" -6 "http://[::1]:<port>/some/path"
```

For a cloud VM, requests from outside also need the port allowed in its network security group
(Azure: VM > Networking > Add inbound port rule, source "My IP address").

In a second PowerShell, check the log:

```powershell
cd $env:USERPROFILE\Desktop\akto-traffic-mirroring-windows-amd64
Select-String -Path .\capture.log -Pattern "capturing on interface|kafka successfully|IP header"
Select-String -Path .\capture.log -Pattern "Kafka write"
```

Expect a `capturing on interface` line per adapter and IP version,
`connection establishing with kafka successfully`, and a `Kafka write successful` line for each
request. The endpoints then appear in the Akto dashboard.

Stop with Ctrl+C, then remove the test rule:

```powershell
Remove-NetFirewallRule -DisplayName "Akto Traffic Mirroring (test)"
```

### 4. Install as a service

```powershell
.\install.ps1 -KafkaUrl "<mini-runtime-ip>:9092" -ExtraEnv @{ DEBUG_URLS = "/some/path" }
Get-Content -Wait -Tail 50 "$env:ProgramData\Akto\logs\mirroring.log"
```

Running `install.ps1` again replaces the existing install. Send some requests again and check the
log. Also check:

- **Recovery:** `Stop-Process -Name mirroring-api-logging -Force` brings the service back
  within about 5 seconds (`Get-Service AktoTrafficMirroring`).
- **Start on boot:** after a reboot, the service is `Running` again.

### 5. Uninstall

```powershell
.\uninstall.ps1          # keeps logs and the collector id
.\uninstall.ps1 -Purge   # removes everything
```

`Get-Service AktoTrafficMirroring` should now fail, and
`Get-NetFirewallRule -DisplayName "Akto*"` should return nothing.

## Configuration

`install.ps1` stores the configuration as the service's environment variables in
`HKLM\SYSTEM\CurrentControlSet\Services\AktoTrafficMirroring\Environment`. To change it, run
`install.ps1` again with all parameters, since it replaces the previous configuration. Any other
variable the module reads on Linux can be passed with `-ExtraEnv`:

```powershell
.\install.ps1 -KafkaUrl "10.0.0.10:9092" -ExtraEnv @{ AKTO_THREAT_ENABLED = "false"; USE_TLS = "true"; TLS_CA_CERT_PATH = "C:\ProgramData\Akto\ca.crt" }
```

| Parameter / variable | Default | Notes |
|---|---|---|
| `-KafkaUrl` / `AKTO_KAFKA_BROKER_URL` | | Required |
| `-MongoConn` / `AKTO_MONGO_CONN` | `mongodb://0.0.0.0:27017/admini` | |
| `-Interface` / `MIRRORING_INTERFACE` | `any` | Comma separated adapter names (`Get-NetAdapter`) or IP addresses |
| `-BatchSize` / `AKTO_TRAFFIC_BATCH_SIZE` | `100` | |
| `-BatchTimeSecs` / `AKTO_TRAFFIC_BATCH_TIME_SECS` | `10` | |
| `AKTO_RESTART_INTERVAL_MINUTES` | `60` | Service restarts itself this often, like `run.sh` on Linux. `0` disables |
| `MAX_LOG_SIZE` | `10485760` | Log file is cleared when it reaches this size in bytes |

Paths such as `TLS_CA_CERT_PATH` must be absolute, since the service runs from
`C:\Windows\System32`.

Files:

| Path | Contents |
|---|---|
| `C:\Program Files\Akto\TrafficMirroring\mirroring-api-logging.exe` | Installed exe |
| `C:\ProgramData\Akto\logs\mirroring.log` | Service log |
| `C:\ProgramData\Akto\collector_id` | Collector id, kept across reinstalls |

## Troubleshooting

| Symptom | Cause |
|---|---|
| `creating raw socket failed` | Not running as Administrator |
| `capturing on interface` lines appear but no traffic is parsed | Windows Firewall or another firewall/antivirus blocks inbound packets for the exe. Check `Get-NetFirewallRule -DisplayName "Akto*"` |
| `IPv6 packets on ... arrive without their IP header` | This Windows version doesn't support IPv6 capture with raw sockets, only IPv4 is captured |
| `no interface matches MIRRORING_INTERFACE` | Wrong adapter name or IP, list them with `Get-NetIPAddress` |
| `error establishing connection with kafka` repeating | Kafka not reachable or advertising an unreachable address, see step 2 |
| Requests to the HTTPS port are never parsed | Traffic is encrypted, only plain HTTP can be read |
| Service stops right after starting | See the log file and Event Viewer > Windows Logs > System |
