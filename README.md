# Welcome to the SOC Toolbelt

## Introduction
Welcome to the SOC Toolbelt, a powerful suite of tools designed to assist in the identification, analysis, and response to security incidents. This toolbelt contains five essential scripts that help security analysts effectively manage and mitigate potential threats within a Windows environment.

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
       $scriptName = [System.IO.Path]::GetFileName($script)
       $destinationPath = "$tempDir\$scriptName"
       Invoke-WebRequest -Uri $script -OutFile $destinationPath
       Write-Output "Downloaded $scriptName"
   }

   # Execute each script sequentially
   foreach ($script in $scripts) {
       $scriptName = [System.IO.Path]::GetFileName($script)
       $scriptPath = "$tempDir\$scriptName"
       Write-Output "Running $scriptName"
       & $scriptPath
       Write-Output "$scriptName completed"
   }

   # Clean up temporary files
   Remove-Item -Recurse -Force $tempDir

