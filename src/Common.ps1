function Write-Message ($message){
	Write-Host "[+] $message"
}

function Write-WarningMessage ($message){
	Write-Host "[!] $message" -ForegroundColor Yellow
}

function Write-ReportableIssue($msg) {
	Write-Warning $msg
	Write-Warning "Please report this issue at https://github.com/joeavanzato/Trawler/issues"
}

function Get-ValidOutPath {
	param (
		[string]
		$path
	)

	if (Test-Path -Path $path -PathType Container)
	{
		Write-Host "The provided path is a folder, not a file. Please provide a file path." -Foregroundcolor "Yellow"
		exit
	}

	return $path
}

function Set-TrawlerPaths {
	try {
		$script:outpath = Get-ValidOutPath -path $outpath
		Write-Message "Detection Output Path: $outpath"
		[System.IO.File]::OpenWrite($outpath).Close()
		$script:output_writable = $true
	}
	catch {
		Write-Warning "Unable to write to provided output path: $outpath"
		$script:output_writable = $false
	}

	if ($snapshot) {
		try {
			$script:snapshotpath = Get-ValidOutPath -path $snapshotpath
			Write-Message "Snapshot Output Path: $snapshotpath"
			[System.IO.File]::OpenWrite($snapshotpath).Close()
			Clear-Content $snapshotpath
			$script:snapshotpath_writable = $true
		}
		catch {
			Write-Warning "Unable to write to provided snapshot path: $snapshotpath"
			$script:snapshotpath_writable = $false
		}
	}
}

function Complete-Run {
	#Start-Sleep -seconds 5
	if ($drivechange){
		foreach ($hive in $new_psdrives_list.GetEnumerator()){
			$hive_key = $hive.Key
			if (Test-Path "Registry::$hive_key"){
				Unpublish-Hive $hive.Key $hive.Value
			}
		}
	}
}

$possibleScanOptions = @(
	"ActiveSetup",
	"AMSIProviders",
	"AppCertDLLs",
	"AppInitDLLs",
	"ApplicationShims",
	"AppPaths",
	"AssociationHijack",
	"AutoDialDLL",
	"BIDDll",
	"BITS",
	"BootVerificationProgram",
	"COMHijacks",
	"CommandAutoRunProcessors",
	"Connections",
	"ContextMenu",
	"DebuggerHijacks",
	"DiskCleanupHandlers",
	"DisableLowIL",
	"DNSServerLevelPluginDLL",
	"eRegChecks",
	"ErrorHandlerCMD",
	"ExplorerHelperUtilities",
	"FolderOpen",
	"GPOExtensions",
	"GPOScripts",
	"HTMLHelpDLL",
	"IFEO",
	"InternetSettingsLUIDll",
	"KnownManagedDebuggers",
	"LNK",
	"LSA",
	"MicrosoftTelemetryCommands",
	"ModifiedWindowsAccessibilityFeature",
	"MSDTCDll",
	"Narrator",
	"NaturalLanguageDevelopmentDLLs",
	"NetSHDLLs",
	"NotepadPPPlugins",
	"OfficeAI",
	"OfficeGlobalDotName",
	"Officetest",
	"OfficeTrustedLocations",
	"OutlookStartup",
	"PATHHijacks",
	"PeerDistExtensionDll",
	"PolicyManager",
	"PowerShellProfiles",
	"PrintMonitorDLLs",
	"PrintProcessorDLLs",
	"Processes",
	"ProcessModules",
	"RATS",
	"RDPShadowConsent",
	"RDPStartupPrograms",
	"RegistryChecks",
	"RemoteUACSetting",
	"ScheduledTasks",
	"SCMDACL",
	"ScreenSaverEXE",
	"SEMgrWallet",
	"ServiceHijacks",
	"Services",
	"SethcHijack",
	"SilentProcessExitMonitoring",
	"Startups",
	"SuspiciousCertificates",
	"SuspiciousFileLocation",
	"TerminalProfiles",
	"TerminalServicesDLL",
	"TerminalServicesInitialProgram",
	"TimeProviderDLLs",
	"TrustProviderDLL",
	"UninstallStrings",
	"UserInitMPRScripts",
	"Users",
	"UtilmanHijack",
	"WellKnownCOM",
	"WERRuntimeExceptionHandlers",
	"WindowsLoadKey",
	"WindowsUnsignedFiles",
	"WindowsUpdateTestDlls",
	"WinlogonHelperDLLs",
	"WMIConsumers",
	"Wow64LayerAbuse"
)

function Write-TrawlerLogo {
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

function Start-Main {
	Write-TrawlerLogo
	Set-TrawlerPaths
	Invoke-DriveChange

	if ($loadsnapshotdata -and $snapshot -eq $false){
		Read-Snapshot
	} elseif ($loadsnapshotdata -and $snapshot) {
		Write-Host "[!] Cannot load and save snapshot simultaneously!" -ForegroundColor "Red"
	}

	if ($ScanOptions -eq "All") {
		$ScanOptions = $possibleScanOptions
	}

	foreach ($option in $ScanOptions){
		switch ($option) {
			"ActiveSetup" { Search-ActiveSetup }
			"AMSIProviders" { Search-AMSIProviders }
			"AppCertDLLs" { Search-AppCertDLLs }
			"AppInitDLLs" { Search-AppInitDLLs }
			"ApplicationShims" { Search-ApplicationShims }
			"AppPaths" { Search-AppPaths }
			"AssociationHijack" { Search-AssociationHijack }
			"AutoDialDLL" { Search-AutoDialDLL }
			"BIDDll" { Search-BIDDll }
			"BITS" { Search-BITS }
			"BootVerificationProgram" { Search-BootVerificationProgram }
			"COMHijacks" { Search-COMHijacks }
			"CommandAutoRunProcessors" { Search-CommandAutoRunProcessors }
			"Connections" { Search-Connections }
			"ContextMenu" { Search-ContextMenu }
			"DebuggerHijacks" { Search-DebuggerHijacks }
			"DNSServerLevelPluginDLL" { Search-DNSServerLevelPluginDLL }
			"DisableLowIL" { Search-DisableLowILProcessIsolation }
			"DiskCleanupHandlers" { Search-DiskCleanupHandlers }
			"eRegChecks" { Search-RegistryChecks }
			"ErrorHandlerCMD" { Search-ErrorHandlerCMD }
			"ExplorerHelperUtilities" { Search-ExplorerHelperUtilities }
			"FolderOpen" { Search-FolderOpen }
			"GPOExtensions" { Search-GPOExtensions }
			"GPOScripts" { Search-GPOScripts }
			"HTMLHelpDLL" { Search-HTMLHelpDLL }
			"IFEO" { Search-IFEO }
			"InternetSettingsLUIDll" { Search-InternetSettingsLUIDll }
			"KnownManagedDebuggers" { Search-KnownManagedDebuggers }
			"LNK" { Search-LNK }
			"LSA" { Search-LSA }
			"MicrosoftTelemetryCommands" { Search-MicrosoftTelemetryCommands }
			"ModifiedWindowsAccessibilityFeature" { Search-ModifiedWindowsAccessibilityFeature }
			"MSDTCDll" { Search-MSDTCDll }
			"Narrator" { Search-Narrator }
			"NaturalLanguageDevelopmentDLLs" { Search-NaturalLanguageDevelopmentDLLs }
			"NetSHDLLs" { Search-NetSHDLLs }
			"NotepadPPPlugins" { Search-NotepadPlusPlusPlugins }
			"OfficeAI" { Search-OfficeAI }
			"OfficeGlobalDotName" { Search-OfficeGlobalDotName }
			"Officetest" { Search-Officetest }
			"OfficeTrustedLocations" { Search-OfficeTrustedLocations }
			"OutlookStartup" { Search-OutlookStartup }
			"PATHHijacks" { Search-PATHHijacks }
			"PeerDistExtensionDll" { Search-PeerDistExtensionDll }
			"PolicyManager" { Search-PolicyManager }
			"PowerShellProfiles" { Search-PowerShellProfiles }
			"PrintMonitorDLLs" { Search-PrintMonitorDLLs }
			"PrintProcessorDLLs" { Search-PrintProcessorDLLs }
			"Processes" { Search-Processes }
			"ProcessModules" { Search-ProcessModules }
			"RATS" { Search-RATS }
			"RDPShadowConsent" { Search-RDPShadowConsent }
			"RDPStartupPrograms" { Search-RDPStartupPrograms }
			# "RegistryChecks" {Search-RegistryChecks}  # Deprecated
			"RemoteUACSetting" { Search-RemoteUACSetting }
			"ScheduledTasks" { Search-ScheduledTasks }
			# "SCMDACL" {Search-SCM-DACL} # TODO
			"ScreenSaverEXE" { Search-ScreenSaverEXE }
			"SEMgrWallet" { Search-SEMgrWallet }
			"ServiceHijacks" { Search-ServiceHijacks }
			"Services" { Search-Services }
			"SethcHijack" { Search-SethcHijack }
			"SilentProcessExitMonitoring" { Search-SilentProcessExitMonitoring }
			"Startups" { Search-Startups }
			"SuspiciousCertificates" { Search-SuspiciousCertificates }
			"SuspiciousFileLocation" { Search-SuspiciousFileLocations }
			"TerminalProfiles" { Search-TerminalProfiles }
			"TerminalServicesDLL" { Search-TerminalServicesDLL }
			"TerminalServicesInitialProgram" { Search-TerminalServicesInitialProgram }
			"TimeProviderDLLs" { Search-TimeProviderDLLs }
			"TrustProviderDLL" { Search-TrustProviderDLL }
			"UninstallStrings" { Search-UninstallStrings }
			"UserInitMPRScripts" { Search-UserInitMPRScripts }
			"Users" { Search-Users }
			"UtilmanHijack" { Search-UtilmanHijack }
			"WellKnownCOM" { Search-WellKnownCOM }
			"WERRuntimeExceptionHandlers" { Search-WERRuntimeExceptionHandlers }
			"WindowsLoadKey" { Search-WindowsLoadKey }
			"WindowsUnsignedFiles" { Search-WindowsUnsignedFiles }
			"WindowsUpdateTestDlls" { Search-WindowsUpdateTestDlls }
			"WinlogonHelperDLLs" { Search-WinlogonHelperDLLs }
			"WMIConsumers" { Search-WMIConsumers }
			"Wow64LayerAbuse" { Search-Wow64LayerAbuse }
		}
	}

	Complete-Run
	Get-TrawlerDetectionMetrics
}

Start-Main