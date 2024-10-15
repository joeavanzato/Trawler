#region Detections

function Write-Detection($det) {
    <#
    .SYNOPSIS
        Receives a 'Detection' - a PowerShell custom object containing specific fields - writes this to Console, EventLog, CSV and a global array for storage depending on specified options.
    #>

    # det is a custom object which will contain various pieces of metadata for the detection
    # Name - The name of the detection logic.
    # Risk (Very Low, Low, Medium, High, Very High)
    # Source - The source 'module' reporting the detection
    # Technique - The most relevant MITRE Technique
    # Meta - Embedded object containing reference material specific to the received detection

    # Validate core fields
    $core_fields = @("Name", "Risk", "Source", "Technique", "Meta")
    foreach ($field in $core_fields) {
        if (-not $($det.PSobject.Properties.Name -contains $field)) {
            Write-Reportable-Issue "Detection Missing '$field' Field! [$det]"
            $det.$($field) = "Error"
            # We will not return for now as there still may be useful information but this is a critical issue
        }
    }

    if (-not (@("Very Low", "Low", "Medium", "High", "Very High") -contains $det.Risk)) {
        Write-Reportable-Issue "Detection has invalid Risk Value: $($det.Risk)"
    }

    # Before anything else, we find all datetime objects within the Meta field of a detection and generate a corresponding UTC timestamp so consumers can use either-or
    if ($det.PSobject.Properties.Name -contains "Meta") {
        $det.Meta.PSObject.Properties | ForEach-Object {
            if ($_.Value -is [datetime]) {
                $tmp = $_.Value
                $det.Meta.$($_.Name) = Format-Datetime $tmp $false
                $det.Meta | Add-Member -NotePropertyName "$($_.Name)_UTC" -NotePropertyValue $(Format-Datetime $tmp $true)
            }
        }
    }

    # If there is no reference, just set it as "N/A" for now
    if (-not $($det.PSobject.Properties.Name -contains "Reference")) {
        $det | Add-Member -MemberType NoteProperty -Name Reference -Value "N/A"
    }

    # Then we do a hash of the detection to determine if it exists in a snapshot - if we are using snapshot and it exists, skip, else, keep going
    $should_we_skip = Check-DetectionInSnapshot($det)
    if ($should_we_skip) {
        $script:suppressed_detections += 1
        return
    }

    $detection_list.Add($det) | Out-Null

    switch ($det.Risk) {
        "Very Low" { $fg_color = "Green" }
        "Low" { $fg_color = "Green" }
        "Medium" { $fg_color = "Yellow" }
        "High" { $fg_color = "Red" }
        "Very High" { $fg_color = "Magenta" }
        Default { $fg_color = "Yellow" }
    }

    # Console Output
    if (-not($Quiet)) {
        Write-Host "[!] Detection: $($det.Name) - Risk: $($det.Risk)" -ForegroundColor $fg_color
        Write-Host "[%] $(Format-MetadataToString($det.Meta))" -ForegroundColor White
    }


}

function Check-DetectionInSnapshot($detection) {
    <#
    .SYNOPSIS
        Receives a detection and checks if it exists in the snapshow allow-list - if so, return $true, else or if we are not using snapshot, return $false
    #>
    # First we check if we are even using a snapshot - if no, then immediately return
    if (-not $snapshot) {
        return $false
    }

    # Return the hash representation of the current detection
    $prepared_detection = Prepare-DetectionForHash $detection
    $jsondetection = $prepared_detection | ConvertTo-Json
    $detection_hash = Get-HashOfString $jsondetection
    $detection_hash # for some reason, this only works when this is here - I have no idea why right now.
    # Check if this already exists in our hash array of the loaded detection snapshot
    if ($detection_hash_array_snapshot -contains $detection_hash) {
        return $true
    }
    else {
        return $false
    }
}

function Prepare-DetectionForHash ($detection) {
    <#
    .SYNOPSIS
        Receives a detection and removes any allow-listed fields from specific detections to improve the fidelity of allow-listing.
    #>
    if ($detection.Name -eq "Established Connection on Suspicious Port") {
        $detection.Meta.PSObject.Properties.Remove('LocalAddress')
        $detection.Meta.PSObject.Properties.Remove('LocalPort')
        $detection.Meta.PSObject.Properties.Remove('PID')
    }

    return $detection
}

function Load-DetectionSnapshot {
    <#
    .SYNOPSIS
        Checks if provided snapshot file is valid and reads the content in order to prepare a list of hashes that represent 'allowed' detections.
    #>
    Write-Message "Reading Snapshot File: $snapshot"
    if (-not (Test-Path -Path $snapshot)) {
        Write-Message "Error - Could not find specified snapshot file: $snapshot"
        return
    }

    $snapshot_detection_count = 0
    $json = Get-Content $snapshot | Out-String | ConvertFrom-Json
    foreach ($det in $json) {
        $detection_prepared = Prepare-DetectionForHash($det)
        $detection_hash = Get-HashOfString $($detection_prepared | ConvertTo-Json)
        $detection_hash_array_snapshot.Add($detection_hash) | Out-Null
        $snapshot_detection_count += 1
    }
    Write-Message "Loaded $snapshot_detection_count Allowed Detections from Snapshot: $snapshot"

}

function Detection-Metrics {
    <#
    .SYNOPSIS
        Presents metrics surrounding all detections to the end-user for a summary view.
    #>
    Write-Host "[!] ### Detection Metadata ###" -ForeGroundColor White
    Write-Message "Total Detections: $($detection_list.Count)"
    Write-Message "Total Suppressed Detections: $suppressed_detections"
    foreach ($str in ($detection_list | Group-Object Risk | Select-Object Name, Count | Out-String).Split([System.Environment]::NewLine)) {
        if (-not ([System.String]::IsNullOrWhiteSpace($str))) {
            Write-Message $str
        }
    }
}

function Emit-Detections {
    <#
    .SYNOPSIS
        Called at the end of the execution flow to emit all detections in the various specified formats.
    #>
    # Emit detections in JSON format
    $detection_list | ConvertTo-Json | Out-File $script:JSONDetectionsPath.Path

    foreach ($det in $detection_list) {
        #EVTX Output
        if ($evtx) {
            Write-DetectionToEVTX $det
        }

        # CSV Output
        $det.Meta = Format-MetadataToString($det.Meta)
        $det | Export-CSV $script:CSVDetectionsPath.Path -Append -NoTypeInformation -Encoding UTF8 -Force
    }

}

#endregion