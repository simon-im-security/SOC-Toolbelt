# Title: Windows Event Logs Analysis
# Description: This script collects the last 10,000 events from the Application and System logs, 
# counts specific security-related event IDs, and generates a CSV report.
# Author: Simon .I
# Version: 2024/08/18

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to run this script as an administrator."
    Exit
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
$csvFilePath = [System.IO.Path]::Combine($folderPath, "windows_event_logs_$timestamp.csv")

# Initialize counters for specific event IDs
$eventCounts = @{
    '1000' = 0  # Application Error
    '1001' = 0  # Windows Error Reporting
    '1002' = 0  # Application Hang
    '3001' = 0  # WMI Issues
    '1026' = 0  # CLR Exception
    '7031' = 0  # Service Control Manager - Service terminated unexpectedly
    '7036' = 0  # Service Control Manager - Service change state
    '7000' = 0  # Service Control Manager - Service failed to start
}

# Function to collect and process events from a specific log
function Process-EventLog {
    param (
        [string]$logName,
        [int]$maxEvents = 10000
    )
    $timeLimit = (Get-Date).AddDays(-30)
    Write-Verbose "Retrieving events from the $logName log..."
    $events = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$timeLimit} -MaxEvents $maxEvents

    # Initialize CSV content for event logs
    $eventRows = ""
    $totalEvents = $events.Count
    $currentEvent = 0

    # Process each event with a progress bar
    foreach ($event in $events) {
        $currentEvent++
        $percentComplete = ($currentEvent / $totalEvents) * 100
        Write-Progress -Activity "Processing $logName Events" -Status "Event $currentEvent of $totalEvents" -PercentComplete $percentComplete

        # Count specific event IDs
        $eventId = "$($event.Id)"
        if ($eventCounts.ContainsKey($eventId)) {
            $eventCounts[$eventId]++
        }

        # Encode the message content for CSV
        $encodedMessage = $event.Message -replace "`n", " " -replace "`r", " " -replace ",", " "

        # Add the event data directly to the eventRows
        $eventRows += "$($event.TimeCreated),$($event.Id),$($event.ProviderName),$logName,$($event.LevelDisplayName),$encodedMessage`n"
    }

    return $eventRows
}

# Prepare the CSV content header
$csvContent = "Time Created,Event ID,Provider,Log Name,Level,Message`n"

# Process Application and System logs and store the CSV rows
$csvContent += Process-EventLog -logName 'Application' -Verbose
$csvContent += Process-EventLog -logName 'System' -Verbose

Write-Output "Finished writing event log data, now writing summary"

# Summary section
$summaryContent = "`nSUMMARY`n"
$summaryContent += "Event ID,Total Count`n"
$summaryContent += "1000 (Application Error),$($eventCounts['1000'])`n"
$summaryContent += "1001 (Windows Error Reporting),$($eventCounts['1001'])`n"
$summaryContent += "1002 (Application Hang),$($eventCounts['1002'])`n"
$summaryContent += "3001 (WMI Issues),$($eventCounts['3001'])`n"
$summaryContent += "1026 (CLR Exception),$($eventCounts['1026'])`n"
$summaryContent += "7031 (Service Terminated),$($eventCounts['7031'])`n"
$summaryContent += "7036 (Service Change State),$($eventCounts['7036'])`n"
$summaryContent += "7000 (Service Failed to Start),$($eventCounts['7000'])`n"

# Next Steps section
$nextStepsContent = "`nNEXT STEPS`n"
$nextStepsContent += "1. **Review Applications:** Identify any applications that consistently generate errors and consider updating, reconfiguring, or uninstalling them if necessary.`n"
$nextStepsContent += "2. **Monitor Services:** Pay close attention to services that frequently stop, start, or fail. This could indicate a deeper issue or potential security risk.`n"
$nextStepsContent += "3. **Investigate WMI and CLR Issues:** Persistent errors in WMI or CLR can affect system performance and stability. Investigate the root cause of these issues.`n"
$nextStepsContent += "4. **Conduct a Security Review:** Services that terminate unexpectedly or fail to start may be targeted by malware. Consider a thorough security review of affected services.`n"

# Write the CSV content to the file
Write-Output "Starting to write event log data to CSV"
$csvContent | Out-File -FilePath $csvFilePath -Encoding utf8
$summaryContent | Out-File -FilePath $csvFilePath -Encoding utf8 -Append
$nextStepsContent | Out-File -FilePath $csvFilePath -Encoding utf8 -Append

Write-Output "Finished writing to CSV"

# Notify the user
Write-Output "Windows Event Logs Analysis has been saved to $csvFilePath"
