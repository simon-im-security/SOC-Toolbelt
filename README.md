# Welcome to the SOC Toolbelt

## Introduction
Welcome to the SOC Toolbelt, a powerful suite of tools designed to assist in the identification, analysis, and response to security incidents. This toolbelt contains five essential scripts that help security analysts effectively manage and mitigate potential threats within a Windows environment.

> **Note:** This toolbelt is designed for **Windows 11** only. A macOS version is coming soon.

## Included Tools

### 1. **Security Event Log Analysis**
   - Analyses security event logs for suspicious activities and potential breaches.

### 2. **User Login Analysis**
   - Reviews user login events to identify unusual or unauthorised access attempts.

### 3. **Windows Event Logs Analysis**
   - Scans general Windows event logs for issues that might indicate a security incident.

### 4. **Network Connection Analysis**
   - Monitors network connections to detect unauthorised or suspicious activities.

### 5. **Process Checker Analysis**
   - Checks running processes for signs of malicious or suspicious behaviour.

## Sample Output

Here’s an example of the type of output you can expect from the SOC Toolbelt:

![Sample Output](https://github.com/simon-im-security/SOC-Toolbelt/blob/main/sample.png?raw=true)

---

## How to Run SOC Tools

To get started with the SOC Toolbelt, follow these steps to download and execute the scripts sequentially.

1. **Open PowerShell as Administrator:**
   - Run PowerShell with elevated privileges to ensure all scripts execute properly.

2. **Download and Execute Scripts:**

   Copy and paste the following commands into your PowerShell window:

   ```powershell
   # Request temporary bypass of execution policy for the session
   Set-ExecutionPolicy Bypass -Scope Process -Force

   # Create a temporary directory
   $tempDir = New-Item -ItemType Directory -Path "$env:TEMP\SOC-Toolbelt"

   # Download each script to the temporary directory
   $scripts = @(
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Network%20Connection%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Windows%20Event%20Logs%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/User%20Login%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Security%20Event%20Log%20Analysis.ps1",
       "https://github.com/simon-im-security/SOC-Toolbelt/blob/main/Process%20Checker%20Analysis.ps1"
   )

   foreach ($script in $scripts) {
       $currentScript++
       $scriptName = [System.IO.Path]::GetFileName($script)
       $scriptPath = "$tempDir\$scriptName"

       # Update the progress bar
       Write-Progress -Activity "Running SOC Toolbelt Scripts" -Status "Running $scriptName" -PercentComplete (($currentScript / $totalScripts) * 100)

       # Real-time status update
       Write-Output "Starting $scriptName at $(Get-Date)"
       
       try {
           Add-Content -Path $logFile -Value "Running $scriptName at $(Get-Date)"
           & $scriptPath -ErrorAction Stop -Verbose *>> $logFile
           Add-Content -Path $logFile -Value "$scriptName completed at $(Get-Date)"
           Write-Output "$scriptName completed at $(Get-Date)"
       } catch {
           $errorMsg = $_.Exception.Message
           $logEntry = "Error running ${scriptName}: ${errorMsg} at $(Get-Date)"
           Add-Content -Path $logFile -Value $logEntry
           Write-Output "Error encountered with $scriptName: $errorMsg"
           continue
       }
   }

   # Complete the progress bar
   Write-Progress -Activity "Running SOC Toolbelt Scripts" -Status "Completed" -PercentComplete 100 -Completed

   # Final real-time update
   Write-Output "All scripts completed at $(Get-Date)"
