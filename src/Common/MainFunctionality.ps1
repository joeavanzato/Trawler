function Clean-Up {
    <#
    .SYNOPSIS
        If we are targeting a non-local drive, clean up all mounted hives
    #>
    #Start-Sleep -seconds 5
    if ($drivechange){
        foreach ($hive in $new_psdrives_list.GetEnumerator()){
            $hive_key = $hive.Key
            if (Test-Path "Registry::$hive_key"){
                Unload-Hive $hive.Key $hive.Value
            }
        }
    }
}

function Logo {
    $logo = "
  __________  ___ _       ____    __________ 
 /_  __/ __ \/   | |     / / /   / ____/ __ \
  / / / /_/ / /| | | /| / / /   / __/ / /_/ /
 / / / _, _/ ___ | |/ |/ / /___/ /___/ _, _/ 
/_/ /_/ |_/_/  |_|__/|__/_____/_____/_/ |_|  
    "
    Write-Host $logo -ForegroundColor White
    Write-Host "Trawler - Dredging Windows for Persistence" -ForegroundColor White
    Write-Host "github.com/joeavanzato/trawler" -ForegroundColor White
    Write-Host ""
}

function Main {
    Logo

    # Check Outputs
    $permissions_ok = Test-OutputDirectoryPermissions
    if (-not $permissions_ok){
        Write-Message "Fatal Error - Could not create/access specified output directory!"
        return
    }

    # Create detection output files
    $script:JSONDetectionsPath = New-TrawlerOutputItem -FileName "detections" -FileType "json"
    $script:CSVDetectionsPath = New-TrawlerOutputItem -FileName "detections" -FileType "csv"
    Write-Message "Detection Output Files: $($script:JSONDetectionsPath.Path), $($script:CSVDetectionsPath.Path)"

    # Setting up required script-level variables
    Drive-Change

    if ($loadsnapshotdata){
        Load-DetectionSnapshot
    }

	if ($ScanOptions -eq "All") {
        $ScanOptions = (Get-Variable "ScanOptions").Attributes.ValidValues
	}

    if ($evtx){
        $evtx_creation_status = Create-EventSource
        if (-not $evtx_creation_status){
            # Fatal Error attempting to create event log
            Write-Message("Fatal Error setting up EventLog Source - are we running as admin?")
            return
        }
    }

	foreach ($option in $ScanOptions){
		switch ($option) {
			"ActiveSetup" { Check-ActiveSetup }
			"AMSIProviders" { Check-AMSIProviders }
			"AppCertDLLs" { Check-AppCertDLLs }
			"AppInitDLLs" { Check-AppInitDLLs }
			"ApplicationShims" { Check-ApplicationShims }
			"AppPaths" { Check-AppPaths }
			"AssociationHijack" { Check-Association-Hijack }
			"AutoDialDLL" { Check-AutoDialDLL }
			"BIDDll" { Check-BIDDll }
			"BITS" { Check-BITS }
            "BootVerificationProgram" { Check-BootVerificationProgram }
			"COMHijacks" { Check-COM-Hijacks }
			"CommandAutoRunProcessors" { Check-CommandAutoRunProcessors }
			"Connections" { Check-Connections }
			"ContextMenu" { Check-ContextMenu }
			"DebuggerHijacks" { Check-Debugger-Hijacks }
			"DNSServerLevelPluginDLL" { Check-DNSServerLevelPluginDLL }
            "DisableLowIL" { Check-DisableLowILProcessIsolation }
            "DirectoryServicesRestoreMode" { Check-DirectoryServicesRestoreMode }
            "DiskCleanupHandlers" { Check-DiskCleanupHandlers }
			"eRegChecks" { Check-Registry-Checks }
			"ErrorHandlerCMD" { Check-ErrorHandlerCMD }
			"ExplorerHelperUtilities" { Check-ExplorerHelperUtilities }
			"FolderOpen" { Check-FolderOpen }
			"GPOExtensions" { Check-GPOExtensions }
			"GPOScripts" { Check-GPO-Scripts }
			"HTMLHelpDLL" { Check-HTMLHelpDLL }
			"IFEO" { Check-IFEO }
            "InstalledSoftware" { Check-InstalledSoftware }
			"InternetSettingsLUIDll" { Check-InternetSettingsLUIDll }
			"KnownManagedDebuggers" { Check-KnownManagedDebuggers }
			"LNK" { Check-LNK }
			"LSA" { Check-LSA }
			"MicrosoftTelemetryCommands" { Check-MicrosoftTelemetryCommands }
			"ModifiedWindowsAccessibilityFeature" { Check-Modified-Windows-Accessibility-Feature }
			"MSDTCDll" { Check-MSDTCDll }
			"Narrator" { Check-Narrator }
			"NaturalLanguageDevelopmentDLLs" { Check-NaturalLanguageDevelopmentDLLs }
			"NetSHDLLs" { Check-NetSHDLLs }
			"NotepadPPPlugins" { Check-Notepad++-Plugins }
			"OfficeAI" { Check-OfficeAI }
			"OfficeGlobalDotName" { Check-OfficeGlobalDotName }
			"Officetest" { Check-Officetest }
			"OfficeTrustedLocations" { Check-Office-Trusted-Locations }
            "OfficeTrustedDocuments"  { Check-OfficeTrustedDocuments }
			"OutlookStartup" { Check-Outlook-Startup }
			"PATHHijacks" { Check-PATH-Hijacks }
			"PeerDistExtensionDll" { Check-PeerDistExtensionDll }
			"PolicyManager" { Check-PolicyManager }
			"PowerShellProfiles" { Check-PowerShell-Profiles }
			"PrintMonitorDLLs" { Check-PrintMonitorDLLs }
			"PrintProcessorDLLs" { Check-PrintProcessorDLLs }
			"Processes" { Check-Processes }
			"ProcessModules" { Check-Process-Modules }
			"RATS" { Check-RATS }
			"RDPShadowConsent" { Check-RDPShadowConsent }
			"RDPStartupPrograms" { Check-RDPStartupPrograms }
			# "RegistryChecks" {Check-Registry-Checks}  # Deprecated
			"RemoteUACSetting" { Check-RemoteUACSetting }
			"ScheduledTasks" { Check-ScheduledTasks }
			"ScreenSaverEXE" { Check-ScreenSaverEXE }
            "ServiceControlManagerSD" {Check-ServiceControlManagerSD }
			"SEMgrWallet" { Check-SEMgrWallet }
			"ServiceHijacks" { Check-Service-Hijacks }
			"Services" { Check-Services }
			"SethcHijack" { Check-SethcHijack }
			"SilentProcessExitMonitoring" { Check-SilentProcessExitMonitoring }
			"Startups" { Check-Startups }
			"SuspiciousCertificates" { Check-Suspicious-Certificates }
			"SuspiciousFileLocation" { Check-Suspicious-File-Locations }
			"TerminalProfiles" { Check-TerminalProfiles }
			"TerminalServicesDLL" { Check-TerminalServicesDLL }
			"TerminalServicesInitialProgram" { Check-TerminalServicesInitialProgram }
			"TimeProviderDLLs" { Check-TimeProviderDLLs }
			"TrustProviderDLL" { Check-TrustProviderDLL }
			"UninstallStrings" { Check-UninstallStrings }
			"UserInitMPRScripts" { Check-UserInitMPRScripts }
			"Users" { Check-Users }
			"UtilmanHijack" { Check-UtilmanHijack }
			"WellKnownCOM" { Check-WellKnownCOM }
			"WERRuntimeExceptionHandlers" { Check-WERRuntimeExceptionHandlers }
			"WindowsLoadKey" { Check-WindowsLoadKey }
			"WindowsUnsignedFiles" { Check-Windows-Unsigned-Files }
			"WindowsUpdateTestDlls" { Check-WindowsUpdateTestDlls }
			"WinlogonHelperDLLs" { Check-WinlogonHelperDLLs }
			"WMIConsumers" { Check-WMIConsumers }
			"Wow64LayerAbuse" { Check-Wow64LayerAbuse }
            "WSL" {Check-WSL }
		}
	}
    Emit-Detections
    Clean-Up
    Detection-Metrics
}

if ($MyInvocation.InvocationName -match ".+.ps1")
{
    Main
}