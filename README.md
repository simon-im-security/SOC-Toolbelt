# Security Operations Centre (SOC) Toolbelt

## Introduction

Welcome to the SOC Toolbelt, a powerful suite of tools designed specifically to assist in responding to security incidents. This toolbelt is ideal for security analysts who need a high-level view of potential threats, complementing existing Endpoint Detection and Response (EDR) tools like CrowdStrike Falcon. 

### Advantages Over Traditional EDR Tools:
- **High-Level View:** The SOC Toolbelt provides a broader perspective, allowing analysts to see the larger picture beyond what standard EDR tools might offer.
- **Empowers Decision-Making:** Rather than automating responses, the toolbelt presents comprehensive data that enables analysts to make informed decisions based on the complete context.
- **Enhanced Communication:** The visibility of this tool to end users supports better communication between security teams and other stakeholders, facilitating clearer explanations and more effective incident response.

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
   $tempDir = "$env:TEMP\SOC-Toolbelt"

   # Check if the directory exists; if so, remove it and create a new one
   if (Test-Path -Path $tempDir) {
       Remove-Item -Recurse -Force -Path $tempDir
   }

   $tempDir = New-Item -ItemType Directory -Path $tempDir

   $logFile = "$tempDir\execution_log.txt"
   $totalScripts = $scripts.Count
   $currentScript = 0

   $scripts = @(
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Network%20Connection%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Windows%20Event%20Logs%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/User%20Login%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Security%20Event%20Log%20Analysis.ps1",
       "https://raw.githubusercontent.com/simon-im-security/SOC-Toolbelt/main/Process%20Checker%20Analysis.ps1"
   )

   foreach ($script in $scripts) {
       $currentScript++
       
       # Decode URL to get the proper filename
       $scriptUri = New-Object System.Uri($script)
       $scriptName = [System.IO.Path]::GetFileName($scriptUri.LocalPath)
       $scriptPath = "$tempDir\$scriptName"

       # Download the script using the raw GitHub URL
       Invoke-WebRequest -Uri $script -OutFile $scriptPath

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
           Write-Output "Error encountered with ${scriptName}: ${errorMsg}"
           continue
       }
   }

   # Complete the progress bar
   Write-Progress -Activity "Running SOC Toolbelt Scripts" -Status "Completed" -PercentComplete 100 -Completed

   # Final real-time update
   Write-Output "All scripts completed at $(Get-Date)"

3. **Execution Notes:**
The script temporarily bypasses the execution policy for the session, allowing the downloaded scripts to run.
After execution, all temporary files are cleaned up automatically.
Always review scripts before executing them to ensure they meet your security standards.
