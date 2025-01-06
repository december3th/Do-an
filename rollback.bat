
$EncryptedPath = "C:\users"
$RecoveryPath = "C:\Recovered_Files"  # Default recovery path, change as needed


$IgnorePaths = @(
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\C:\Recovered_Files"  # Add more paths as needed
)


$LogFile = "$RecoveryPath\RecoveryLog.txt"


$LogFileDirectory = [System.IO.Path]::GetDirectoryName($LogFile)
if (-not (Test-Path -Path $LogFileDirectory)) {
    New-Item -Path $LogFileDirectory -ItemType Directory -Force
}


if (Test-Path -Path $LogFile) {
    Clear-Content -Path $LogFile
} else {
    New-Item -Path $LogFile -ItemType File
}


function Log-Message {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp - $Message"
    Write-Host "$Timestamp - $Message"
}

try {
    Log-Message "Starting recovery process..."

    start-sleep 120
    cmd /c sc config VSS start=Demand
    cmd /c net start VSS
    start-sleep 5
    Log-Message "Listing shadow copies..."
    
    # Extract the shadow copy volume path using Select-String
    $ShadowCopyVolumes = C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe -c "Get-WmiObject -Query 'SELECT * FROM Win32_ShadowCopy' | Select-Object -ExpandProperty DeviceObject"

    if ($ShadowCopyVolumes.Count -gt 0) {
        $ShadowCopyVolume = $ShadowCopyVolumes[-1]  # Select the last shadow copy volume
        Log-Message "Latest Shadow Copy Volume found: $ShadowCopyVolume"
    } else {
        throw "Unable to find Shadow Copy Volume path in vssadmin output."
    }

    # Ensure ShadowCopyVolume ends with a backslash
    if (-not $ShadowCopyVolume.EndsWith("\")) {
        $ShadowCopyVolume += "\"
    }

    Log-Message "Adjusted Shadow Copy Volume path: $ShadowCopyVolume"

    $LinkPath = Join-Path -Path $RecoveryPath -ChildPath "backup"
    Log-Message "Creating symbolic link at $LinkPath..."

    if (Test-Path -Path $LinkPath) {
        Remove-Item -Path $LinkPath -Recurse -Force
        Log-Message "Existing symbolic link or folder removed at $LinkPath"
    }

    $linkCmdOutput = cmd /c mklink /d "$LinkPath" "$ShadowCopyVolume"
    Log-Message "Symbolic link command output: $linkCmdOutput"

    # Verify symbolic link creation
    if (-not (Test-Path -Path $LinkPath)) {
        throw "Failed to create symbolic link at $LinkPath"
    }
    Log-Message "Symbolic link created successfully: $LinkPath -> $ShadowCopyVolume"

    Write-Host "Files restore completed."
    "Wazuh_Ransomware_Protection: File restore completed for $($env:computername) at $(Get-Date)" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding UTF8
}
catch {
    $ErrorMsg = $Error[0].ToString()
    Log-Message "Error: $ErrorMsg"
    Write-Error "An error occurred: $ErrorMsg"
}

    # Stop VSS service
    cmd /c sc config VSS start=disabled
    cmd /c net stop VSS
    start-sleep 5
    Log-Message "Turned off VSS service..."
