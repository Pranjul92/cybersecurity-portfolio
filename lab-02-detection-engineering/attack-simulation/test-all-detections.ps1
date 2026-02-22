<#
    Lab 2 Detection Testing Script: Executes simulated attacks to trigger all 6 detection rules to validate that SIEM detections are working. 
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Lab 2: Detection Testing Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Detection 1: Brute Force Login
Write-Host "[1/6] Testing Brute Force Detection..." -ForegroundColor Yellow
1..10 | ForEach-Object {
    runas /user:fakeuser$_ cmd 2>$null
    Start-Sleep -Milliseconds 500
}
Write-Host "  ✓ Generated 10 failed login attempts`n" -ForegroundColor Green

# Detection 2: Encoded PowerShell
Write-Host "[2/6] Testing Encoded PowerShell Detection..." -ForegroundColor Yellow
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Get-Process"))
powershell.exe -encodedcommand $encoded
Write-Host "  ✓ Executed encoded PowerShell command`n" -ForegroundColor Green

# Detection 3: PowerShell Download Cradle
Write-Host "[3/6] Testing Download Cradle Detection..." -ForegroundColor Yellow
cd $env:TEMP
Invoke-WebRequest -Uri "https://www.google.com" -OutFile "test.html" -ErrorAction SilentlyContinue
Remove-Item "test.html" -ErrorAction SilentlyContinue
Write-Host "  ✓ Executed Invoke-WebRequest`n" -ForegroundColor Green

# Detection 4: LOLBin Execution
Write-Host "[4/6] Testing LOLBin Detection..." -ForegroundColor Yellow
certutil -encode C:\Windows\System32\drivers\etc\hosts "$env:TEMP\encoded.txt"
Remove-Item "$env:TEMP\encoded.txt" -ErrorAction SilentlyContinue
Write-Host "  ✓ Executed certutil.exe`n" -ForegroundColor Green

# Detection 5: Office Spawning Shell
Write-Host "[5/6] Testing Office Shell Spawn Detection..." -ForegroundColor Yellow
Write-Host "  ⚠ Skipping - requires manual Word macro execution" -ForegroundColor DarkYellow
Write-Host "  ℹ To test: Open Word → Alt+F11 → Run macro`n" -ForegroundColor Gray

# Detection 6: Admin Account Creation
Write-Host "[6/6] Testing Admin Account Creation Detection..." -ForegroundColor Yellow
try {
    net user testadmin Password123! /add 2>$null
    net localgroup Administrators testadmin /add 2>$null
    Start-Sleep -Seconds 2
    net localgroup Administrators testadmin /delete 2>$null
    net user testadmin /delete 2>$null
    Write-Host "  ✓ Created and removed test admin account`n" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed - requires Administrator privileges`n" -ForegroundColor Red
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Execution Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Next Steps:" -ForegroundColor White
Write-Host "1. Wait 10 minutes for alerts to trigger" -ForegroundColor Gray
Write-Host "2. Check Splunk: Activity → Triggered Alerts" -ForegroundColor Gray
Write-Host "3. Verify all 6 detections fired" -ForegroundColor Gray
Write-Host "`nExpected Alerts:" -ForegroundColor White
Write-Host "  [1] Failed Login Brute Force Detection" -ForegroundColor Gray
Write-Host "  [2] PowerShell Encoded Command Execution" -ForegroundColor Gray
Write-Host "  [3] PowerShell Download Cradle Detected" -ForegroundColor Gray
Write-Host "  [4] Living-off-the-Land Binary Execution" -ForegroundColor Gray
Write-Host "  [5] Office Application Spawning Shell (manual)" -ForegroundColor Gray
Write-Host "  [6] New Administrator Account Created" -ForegroundColor Gray
Write-Host ""
