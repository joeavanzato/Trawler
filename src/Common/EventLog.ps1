#region EventLogging

function Create-EventSource {
    <#
    .SYNOPSIS
        Creates an Event Source inside the Application event log to store detections as JSON
    #>
    Write-Message("Attempting to create Event Log Source: $evtx_source")
    if (-not [System.Diagnostics.EventLog]::SourceExists($evtx_source)) {
        # Source does not exist
        try {
            New-EventLog -LogName $evtx_logname -Source $evtx_source
            Write-Message("Successfully created Event Log Source: $evtx_source")
            # Created ok
            return $true
        }
        catch {
            # Error creating
            Write-Message("Failed to create Event Log Source: $evtx_source")
            return $false
        }
    }
    else {
        # Source already exists
        Write-Message("Event Log Source already exists")
        return $true
    }
}

function Write-DetectionToEVTX($detection) {
    <#
    .SYNOPSIS
        Writes inbound detections to the associated Event Log and Source as a JSON blob
    #>
    # TODO - Give each detection their own EID
    # TODO - Evaluate breaking up k=v of each detection similar to how PersistenceSniper does this as below:
    # snippet borrowed from PS https://github.com/last-byte/PersistenceSniper/pull/18/files#diff-594bab796584c8283d08be6a7120923a730f027fe8e213952a932de851f3eaf1R2036
    <#    foreach ($finding in $Findings) {
          $evtID = $EventIDMapping[$finding.technique]
          $id = New-Object System.Diagnostics.EventInstance($evtID, 1); # Info Event
          $propertiesValue = $finding.PSObject.Properties | Select-Object -ExpandProperty Value
          $evtObject = New-Object System.Diagnostics.EventLog;
          $evtObject.Log = $evtlog;
          $evtObject.Source = $source;
          $evtObject.WriteEvent($id, $propertiesValue)
        }#>
    Write-EventLog -LogName $evtx_logname -Source $evtx_source -EventID 9001 -EntryType Information -Message $($detection | ConvertTo-Json) -ErrorAction SilentlyContinue
}

#endregion