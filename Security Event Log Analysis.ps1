# Title: Security Event Log Analysis
# Description: This script collects Security event logs from the last 30 days and generates a CSV report.
# The report includes a detailed log and a combined summary at the bottom, with explanations of error codes.
# The output is saved as a CSV file in the "Security Operations" folder on the user's Desktop,
# with a progress bar shown during processing.
# Author: Simon .I
# Version: 2024.08.21
# Execution as Administrator is Required.

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
$logFilePath = [System.IO.Path]::Combine($folderPath, "security_event_logs_$timestamp.csv")

# Initialize an array for storing log data
$logData = @()

# Initialize counters for summary
$logonSuccessCount = 0
$logonFailureCount = 0
$explicitLogonCount = 0
$permissionChangeCount = 0
$specialPrivilegesCount = 0
$privilegedServiceCallCount = 0
$userRightAssignedCount = 0
$accountCreatedCount = 0
$accountDeletedCount = 0
$accountChangedCount = 0
$accountLockoutCount = 0
$computerAccountChangedCount = 0
$groupMemberAddedCount = 0
$accountUnlockedCount = 0
$localGroupEnumCount = 0
$secGroupEnumCount = 0
$integrityViolationCount = 0
$credentialReadCount = 0

# Step 1: Collect the last 10,000 Security Event Logs from the last 30 days
$timeLimit = (Get-Date).AddDays(-30)
$securityEvents = Get-WinEvent -FilterHashtable @{LogName="Security"; StartTime=$timeLimit} -MaxEvents 10000

# Get total number of events for progress tracking
$totalEvents = $securityEvents.Count
$currentEvent = 0

# Process each event and update the progress bar
foreach ($event in $securityEvents) {
    $currentEvent++
    $percentComplete = ($currentEvent / $totalEvents) * 100
    Write-Progress -Activity "Processing Security Events" -Status "Event $currentEvent of $totalEvents" -PercentComplete $percentComplete

    # Add event data to the array
    $logData += [PSCustomObject]@{
        Section = "Event Logs"
        TimeCreated = $event.TimeCreated
        EventID = $event.Id
        Provider = $event.ProviderName
        Level = $event.LevelDisplayName
        Message = $event.Message
    }

    # Update counters based on event ID
    switch ($event.Id) {
        4624 { $logonSuccessCount++ }
        4625 { $logonFailureCount++ }
        4648 { $explicitLogonCount++ }
        4670 { $permissionChangeCount++ }
        4672 { $specialPrivilegesCount++ }
        4673 { $privilegedServiceCallCount++ }
        4704 { $userRightAssignedCount++ }
        4720 { $accountCreatedCount++ }
        4726 { $accountDeletedCount++ }
        4738 { $accountChangedCount++ }
        4740 { $accountLockoutCount++ }
        4742 { $computerAccountChangedCount++ }
        4756 { $groupMemberAddedCount++ }
        4767 { $accountUnlockedCount++ }
        4798 { $localGroupEnumCount++ }
        4799 { $secGroupEnumCount++ }
        5038 { $integrityViolationCount++ }
        5379 { $credentialReadCount++ }
    }
}

# Add a blank line to separate the log data from the summary
$logData += [PSCustomObject]@{ Section = ""; TimeCreated = ""; EventID = ""; Provider = ""; Level = ""; Message = "" }

# Step 2: Add summary data to the array
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = ""; EventID = ""; Provider = ""; Level = ""; Message = "" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4624"; EventID = "Successful Logon"; Provider = ""; Level = ""; Message = "$logonSuccessCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4625"; EventID = "Failed Logon"; Provider = ""; Level = ""; Message = "$logonFailureCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4648"; EventID = "Explicit Credential Logon"; Provider = ""; Level = ""; Message = "$explicitLogonCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4670"; EventID = "Permission Change"; Provider = ""; Level = ""; Message = "$permissionChangeCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4672"; EventID = "Special Privileges"; Provider = ""; Level = ""; Message = "$specialPrivilegesCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4673"; EventID = "Privileged Service Call"; Provider = ""; Level = ""; Message = "$privilegedServiceCallCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4704"; EventID = "User Right Assigned"; Provider = ""; Level = ""; Message = "$userRightAssignedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4720"; EventID = "User Account Created"; Provider = ""; Level = ""; Message = "$accountCreatedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4726"; EventID = "User Account Deleted"; Provider = ""; Level = ""; Message = "$accountDeletedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4738"; EventID = "User Account Changed"; Provider = ""; Level = ""; Message = "$accountChangedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4740"; EventID = "Account Lockout"; Provider = ""; Level = ""; Message = "$accountLockoutCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4742"; EventID = "Computer Account Changed"; Provider = ""; Level = ""; Message = "$computerAccountChangedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4756"; EventID = "Group Membership Added"; Provider = ""; Level = ""; Message = "$groupMemberAddedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4767"; EventID = "Account Unlocked"; Provider = ""; Level = ""; Message = "$accountUnlockedCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4798"; EventID = "Local Group Membership Enumerated"; Provider = ""; Level = ""; Message = "$localGroupEnumCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "4799"; EventID = "Security Group Membership Enumerated"; Provider = ""; Level = ""; Message = "$secGroupEnumCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "5038"; EventID = "Integrity Violation"; Provider = ""; Level = ""; Message = "$integrityViolationCount" }
$logData += [PSCustomObject]@{ Section = "SUMMARY"; TimeCreated = "5379"; EventID = "Credential Manager Credentials Read"; Provider = ""; Level = ""; Message = "$credentialReadCount" }

# Add a blank line to separate the summary from the explanations
$logData += [PSCustomObject]@{ Section = ""; TimeCreated = ""; EventID = ""; Provider = ""; Level = ""; Message = "" }

# Step 3: Add explanation
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = ""; EventID = ""; Provider = ""; Level = ""; Message = "" }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4624"; EventID = "Successful Logon"; Provider = ""; Level = ""; Message = "Indicates a successful login. These events are common and usually indicate normal user activity." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4625"; EventID = "Failed Logon"; Provider = ""; Level = ""; Message = "Indicates a failed login attempt. Can occur due to incorrect passwords or other login issues, which might be normal if users frequently mistype passwords." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4648"; EventID = "Explicit Credential Logon"; Provider = ""; Level = ""; Message = "Occurs when a logon is attempted using explicit credentials, such as a Run As command. Could be normal in administrative tasks." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4670"; EventID = "Permission Change"; Provider = ""; Level = ""; Message = "Occurs when permissions on an object are modified. Common during administrative changes." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4672"; EventID = "Special Privileges"; Provider = ""; Level = ""; Message = "Assigned during logon for accounts with elevated privileges. Normal for administrative logons." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4673"; EventID = "Privileged Service Call"; Provider = ""; Level = ""; Message = "Occurs when a privileged service is called. Typical in environments where services require elevated access." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4704"; EventID = "User Right Assigned"; Provider = ""; Level = ""; Message = "Happens when a user right is assigned. Common during system configuration or user management." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4720"; EventID = "User Account Created"; Provider = ""; Level = ""; Message = "Indicates the creation of a new user account. Normal if done by administrators." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4726"; EventID = "User Account Deleted"; Provider = ""; Level = ""; Message = "Indicates the deletion of a user account. Expected during user management activities." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4738"; EventID = "User Account Changed"; Provider = ""; Level = ""; Message = "Indicates changes to an existing user account. Normal during account management or administrative updates." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4740"; EventID = "Account Lockout"; Provider = ""; Level = ""; Message = "Occurs when a user account is locked out due to too many failed login attempts. Normal in environments with strict security policies." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4742"; EventID = "Computer Account Changed"; Provider = ""; Level = ""; Message = "Happens when changes are made to a computer account, such as resetting its password. Common during routine maintenance." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4756"; EventID = "Group Membership Added"; Provider = ""; Level = ""; Message = "Indicates that a member was added to a security-enabled universal group. Normal for user or group management." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4767"; EventID = "Account Unlocked"; Provider = ""; Level = ""; Message = "Occurs when a locked account is unlocked. Expected when an administrator unlocks a user's account." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4798"; EventID = "Local Group Membership Enumerated"; Provider = ""; Level = ""; Message = "Indicates that a user's local group membership was enumerated. Could be normal in audit or management scripts." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "4799"; EventID = "Security Group Membership Enumerated"; Provider = ""; Level = ""; Message = "Occurs when security group membership is enumerated. Common in security auditing or system checks." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "5038"; EventID = "Integrity Violation"; Provider = ""; Level = ""; Message = "Indicates a code integrity violation. Can occur if a file's hash does not match its expected value. Might be normal if software updates or installations are in progress." }
$logData += [PSCustomObject]@{ Section = "EXPLANATION"; TimeCreated = "5379"; EventID = "Credential Manager Credentials Read"; Provider = ""; Level = ""; Message = "Occurs when credentials stored in the Credential Manager are read. Could be normal in legitimate system processes but might require further investigation if unexpected." }

# Step 4: Export log data to CSV
$logData | Export-Csv -Path $logFilePath -NoTypeInformation

# Clear the progress bar
Write-Progress -Activity "Completed" -Status "All steps completed" -Completed

# Notify the user
Write-Output "Security Event Logs Analysis has been saved to $logFilePath"
