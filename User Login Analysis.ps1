# Title: User Login Analysis
# Description: This script retrieves all users who have successfully logged in to the system, including RDP and remote session attempts,
# by analysing Security Event Logs for Event ID 4624 (Successful Logon) and Event ID 4625 (Failed Logon).
# The output is saved as a CSV file in the "Security Operations" folder on the user's Desktop, 
# showing the logon type, username, domain, logon time, and a summary with a user login count.
# Author: Simon .I
# Version: 2024.08.18

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to run this script as an administrator."
    Exit
}

# Function to determine the logon type
function Get-LogonType {
    param([string]$logonType)
    switch ($logonType) {
        '2' { return "Interactive (Local Logon)" }
        '3' { return "Network (Remote File Access or RDP)" }
        '4' { return "Batch" }
        '5' { return "Service" }
        '7' { return "Unlock" }
        '8' { return "NetworkCleartext (RDP)" }
        '9' { return "NewCredentials" }
        '10' { return "RemoteInteractive (RDP)" }
        '11' { return "CachedInteractive (Local Logon)" }
        default { return "Unknown" }
    }
}

# Define the folder path for "Security Operations"
$folderPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), "Security Operations")

# Create the "Security Operations" folder if it doesn't exist
if (-not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}

# Get the current date and time in a format suitable for a file name
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

# Define the log file path in the "Security Operations" folder with the timestamp
$logFilePath = [System.IO.Path]::Combine($folderPath, "user_login_history_$timestamp.csv")

# Prepare the CSV content header
$csvContent = "Logon Time,User Name,Domain,Logon Type,Status`n"

# Hashtable to count logins per user
$userCount = @{}

# Get the Security Event Logs for Event ID 4624 (Successful Logon) and Event ID 4625 (Failed Logon)
$events = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4624, 4625)} | ForEach-Object {
    $logonTypeValue = $_.Properties[8].Value

    # Handle logon type as string without casting to int
    $logonType = Get-LogonType -logonType $logonTypeValue

    $userName = $_.Properties[5].Value
    $domain = $_.Properties[6].Value
    $status = if ($_.Id -eq 4624) { "Success" } else { "Failed" }
    $timeCreated = $_.TimeCreated

    # Count logins per user
    if ($userCount.ContainsKey($userName)) {
        $userCount[$userName]++
    } else {
        $userCount[$userName] = 1
    }

    # Append event data to the CSV report
    $csvContent += "$timeCreated,$userName,$domain,$logonType,$status`n"
}

# Prepare the summary section
$summaryContent = "`nSUMMARY`n"
$summaryContent += "User Name,Login Count`n"
foreach ($user in $userCount.Keys) {
    $loginCount = $userCount[$user]
    $summaryContent += "$user,$loginCount`n"
}

# Add next steps content
$nextStepsContent = "`nNEXT STEPS`n"
$nextStepsContent += "1. Review any users with a high number of failed logon attempts for potential security risks.`n"
$nextStepsContent += "2. Investigate any unusual logon types, such as unexpected RemoteInteractive or NetworkCleartext logons.`n"
$nextStepsContent += "3. Cross-check successful logins against known user activities to ensure no unauthorized access occurred.`n"

# Append the summary and next steps to the CSV
$csvContent += $summaryContent
$csvContent += $nextStepsContent

# Write the CSV content to the file with UTF-8 encoding
$csvContent | Out-File -FilePath $logFilePath -Encoding utf8

# Notify the user
Write-Output "The user login and remote session history has been saved to $logFilePath"
