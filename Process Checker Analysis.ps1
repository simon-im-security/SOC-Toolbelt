# Title: Process Checker Analysis
# Description: This script lists all running processes, displays their paths, and saves the output to a CSV file
# with a focused risk assessment. Processes running from locations outside of Windows or Program Files directories,
# with suspicious names, or lacking valid digital signatures are flagged as possible risks in the summary, with specific reasons provided for each.
# Author: Simon.I
# Version: 2024.08.21

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to run this script as an administrator."
    Exit
}

# Define variables
$outputFolder = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), "Security Operations")
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outputFile = [System.IO.Path]::Combine($outputFolder, "process_checker_analysis_$timestamp.csv")

# Create output folder if it doesn't exist
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory
}

# Initialize an array for storing process data
$processData = @()

# Define a regex pattern for detecting suspicious characters in process names
$oddNamePattern = '[^a-zA-Z0-9_\-\.]'

# Initialize counters for the summary
$totalProcessesFlagged = 0
$outsideDirectoriesCount = 0
$suspiciousNameCount = 0
$invalidSignatureCount = 0

# Get all running processes
$processes = Get-Process | Where-Object { $_.Path -ne $null }

# Initialize progress bar
$totalProcesses = $processes.Count
$currentProcess = 0

foreach ($process in $processes) {
    $currentProcess++
    $progressPercentage = ($currentProcess / $totalProcesses) * 100
    Write-Progress -Activity "Analyzing Processes" -Status "Processing $currentProcess of $totalProcesses" -PercentComplete $progressPercentage

    $processName = $process.Name
    $processPath = $process.Path
    $signatureStatus = "Not checked"

    # Initialize reason for flagging the process
    $reason = $null

    # Check if process is outside of standard system directories
    if ($processPath -notlike "C:\Windows\*" -and $processPath -notlike "C:\Program Files\*" -and $processPath -notlike "C:\Program Files (x86)\*") {
        $reason = "Running outside of Windows or Program Files directories."
        $outsideDirectoriesCount++
    }

    # Check for suspicious characters in the process name
    if ($processName -match $oddNamePattern) {
        if ($reason) {
            $reason += "; Name contains suspicious characters."
        } else {
            $reason = "Name contains suspicious characters."
        }
        $suspiciousNameCount++
    }

    # Check for valid digital signature, ensuring processPath is not null
    if ($processPath) {
        $signature = Get-AuthenticodeSignature -FilePath $processPath
        $signatureStatus = $signature.Status
        if ($signatureStatus -ne 'Valid') {
            if ($reason) {
                $reason += "; Invalid or missing digital signature."
            } else {
                $reason = "Invalid or missing digital signature."
            }
            $invalidSignatureCount++
        }
    }

    # If the process is flagged for any reason, increase the total flagged count
    if ($reason) {
        $totalProcessesFlagged++
    }

    # Add process data to the array
    $processData += [PSCustomObject]@{
        Name = $processName
        Path = $processPath
        Signature = $signatureStatus
        RiskReason = $reason
    }
}

# Export process data to CSV
$processData | Export-Csv -Path $outputFile -NoTypeInformation

# Append summary to the CSV
$summaryData = @()
$summaryData += [PSCustomObject]@{ Name = ""; Path = ""; Signature = ""; RiskReason = "" }  # Blank line for separation
$summaryData += [PSCustomObject]@{ Name = "SUMMARY"; Path = ""; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Total Processes Analyzed"; Path = $totalProcesses; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Total Processes Flagged"; Path = $totalProcessesFlagged; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Processes Running Outside Standard Directories"; Path = $outsideDirectoriesCount; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Processes with Suspicious Names"; Path = $suspiciousNameCount; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Processes with Invalid or Missing Signatures"; Path = $invalidSignatureCount; Signature = ""; RiskReason = "" }

$summaryData += [PSCustomObject]@{ Name = ""; Path = ""; Signature = ""; RiskReason = "" }  # Blank line for separation
$summaryData += [PSCustomObject]@{ Name = "EXPLANATION"; Path = ""; Signature = ""; RiskReason = "" }
$summaryData += [PSCustomObject]@{ Name = "Running outside of Windows or Program Files directories"; Path = ""; Signature = ""; RiskReason = "Processes running from non-standard directories may be at higher risk as they could be bypassing security controls or executing from unusual locations." }
$summaryData += [PSCustomObject]@{ Name = "Name contains suspicious characters"; Path = ""; Signature = ""; RiskReason = "Suspicious characters in process names may indicate attempts to obfuscate malicious activity or avoid detection by security tools." }
$summaryData += [PSCustomObject]@{ Name = "Invalid or missing digital signature"; Path = ""; Signature = ""; RiskReason = "Lack of a valid digital signature may suggest that the process is not from a trusted source, and it may warrant further investigation." }

$summaryData | Export-Csv -Path $outputFile -NoTypeInformation -Append

# Notify user and display output file location
Write-Output "Process check completed. The output has been saved to $outputFile"
