# Title: Network Connection Analysis
# Description: This script lists all TCP and UDP connections the computer is currently connected to,
# excluding loopback addresses, and retrieves the associated process name, 
# service name, country (using ip-api.com), local and remote ports, and process path for each IP address.
# The output is saved as a CSV file in the "Security Operations" folder on the user's Desktop,
# with a progress bar shown during processing. The output file name includes the current date and time.
# Author: Simon .I
# Version: 2024.08.17

# Hashtable for caching IP lookups
$ipCache = @{}

# Function to get the country of an IP address using ip-api.com
function Get-CountryBatch {
    param(
        [string[]]$IPs
    )

    # Prepare the batch request
    $url = "http://ip-api.com/batch"
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body ($IPs | ConvertTo-Json)
        return $response
    } catch {
        return @()
    }
}

# Function to resolve service name from IP address
function Get-ServiceName {
    param(
        [string]$IP
    )

    try {
        $service = [System.Net.Dns]::GetHostEntry($IP)
        return $service.HostName
    } catch {
        return "Unknown"
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
$logFilePath = [System.IO.Path]::Combine($folderPath, "network_analysis_$timestamp.csv")

# Get all active TCP and UDP connections, filter out loopback and local addresses
$tcpConnections = Get-NetTCPConnection | Where-Object {
    $_.RemoteAddress -ne '::' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '0.0.0.0'
} | Select-Object -Property RemoteAddress, LocalPort, RemotePort, OwningProcess

$udpConnections = Get-NetUDPEndpoint | Where-Object {
    $_.RemoteAddress -ne '::' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '0.0.0.0'
} | Select-Object -Property RemoteAddress, LocalPort, RemotePort, OwningProcess

# Combine TCP and UDP connections
$connections = $tcpConnections + $udpConnections

# Prepare the CSV content header
$csvContent = "IP Address,Process Name,Service Name,Country,Local Port,Remote Port,Process Path,Protocol`n"

# Cache to store resolved IP addresses
$ipCache = @{}
$batchSize = 100
$totalConnections = $connections.Count
$currentConnection = 0

# Counters for summary
$totalTCPConnections = 0
$totalUDPConnections = 0
$countries = @()

# Process connections in batches
$connections | Group-Object -Property RemoteAddress -NoElement | ForEach-Object -Begin {
    $batch = @()
} -Process {
    $remoteIP = $_.Name

    if (-not [string]::IsNullOrEmpty($remoteIP) -and -not $ipCache.ContainsKey($remoteIP)) {
        $batch += $remoteIP
    }

    if ($batch.Count -ge $batchSize) {
        $batchResults = Get-CountryBatch -IPs $batch
        foreach ($result in $batchResults) {
            $ipCache[$result.query] = $result.country
        }
        $batch = @()
    }

} -End {
    if ($batch.Count -gt 0) {
        $batchResults = Get-CountryBatch -IPs $batch
        foreach ($result in $batchResults) {
            $ipCache[$result.query] = $result.country
        }
    }

    foreach ($conn in $connections) {
        $currentConnection++
        $progressPercentage = ($currentConnection / $totalConnections) * 100
        Write-Progress -Activity "Processing Connections" -Status "Processing $currentConnection of $totalConnections" -PercentComplete $progressPercentage

        $remoteIP = $conn.RemoteAddress
        $process = Get-Process -Id $conn.OwningProcess
        $processName = $process.ProcessName
        $processPath = $process.Path

        # Check if the IP is not null or empty and if it's in the cache
        if (-not [string]::IsNullOrEmpty($remoteIP) -and $ipCache.ContainsKey($remoteIP)) {
            $country = $ipCache[$remoteIP]
            $countries += $country
        } else {
            $country = "Unknown"
        }

        $serviceName = Get-ServiceName -IP $remoteIP
        $protocol = if ($conn.PSObject.Properties.Match('OwningProcess').Count -gt 0) {
            $totalTCPConnections++
            "TCP"
        } else {
            $totalUDPConnections++
            "UDP"
        }

        $csvContent += "$remoteIP,$processName,$serviceName,$country,$($conn.LocalPort),$($conn.RemotePort),$processPath,$protocol`n"
    }
}

# Write the CSV content to the file with UTF-8 encoding
$csvContent | Out-File -FilePath $logFilePath -Encoding utf8

# Prepare the summary
$summaryContent = "`nSUMMARY`n"
$summaryContent += "Total TCP Connections: $totalTCPConnections`n"
$summaryContent += "Total UDP Connections: $totalUDPConnections`n"
$summaryContent += "Unique Countries Connected To: " + ($countries | Sort-Object -Unique | Measure-Object).Count + "`n"

# Append the summary to the CSV
Add-Content -Path $logFilePath -Value $summaryContent

# Notify the user
Write-Output "The network connection details and summary have been saved to $logFilePath"
