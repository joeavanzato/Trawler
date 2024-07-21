<#
	.SYNOPSIS
		trawler helps Incident Responders discover suspicious persistence mechanisms on Windows devices.
	
	.DESCRIPTION
		trawler inspects a wide variety of Windows artifacts to help discover signals of persistence including the registry, scheduled tasks, services, startup items, etc.
		For a full list of artifacts, please see github.com/joeavanzato/trawler

	.PARAMETER outpath
		The fully-qualified file-path where detection output should be stored as a CSV

	.PARAMETER snapshot
		If specified, tells trawler to capture a persistence snapshot

	.PARAMETER hide
		If specified, tells trawler to suppress detection output to console

	.PARAMETER snapshotpath
		The fully-qualified file-path where snapshot output should be stored - defaults to $PSScriptRoot\snapshot.csv

	.PARAMETER loadsnapshot
		The fully-qualified file-path to a previous snapshot to be loaded for allow-listing

	.PARAMETER ScanOptions
		Set to pick specific scanners to run. Multiple can be used when separated by a comma. (Supports tab completion)

	.EXAMPLE
		.\trawler.ps1 -outpath "C:\detections.csv"

	.EXAMPLE
		.\trawler.ps1 -outpath "C:\detections.csv" -ScanOptions ScheduledTasks, BITS
	
	.OUTPUTS
		None
	
	.NOTES
		None
	
	.INPUTS
		None
	
	.LINK
		https://github.com/joeavanzato/Trawler
#>
[CmdletBinding()]
param
(
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where detection output should be stored as a CSV, defaults to $PSScriptRoot\detections.csv')]
	[string]
	$outpath = "$PSScriptRoot\detections.csv",
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Should a snapshot CSV be generated')]
	[switch]
	$snapshot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Suppress Detection Output to Console')]
	[switch]
	$Quiet,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where persistence snapshot output should be stored as a CSV, defaults to $PSScriptRoot\snapshot.csv')]
	[string]
	$snapshotpath = "$PSScriptRoot\snapshot.csv",
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where the snapshot CSV to be loaded is located')]
	[string]
	$loadsnapshot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The drive to target for analysis - for example, if mounting an imaged system as a second drive on an analysis device, specify via -drivetarget "D:" (NOT YET IMPLEMENTED)')]
	[string]
	$drivetarget,
	[Parameter(
		Mandatory = $false,
		HelpMessage = "Allows for targeting certain scanners and ignoring others. Use 'All' to run all scanners.")]
	[ValidateSet(
		"ActiveSetup",
		"All",
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
		"DisableLowIL",
		"DiskCleanupHandlers",
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
	)]
	$ScanOptions = "All"
)

$drivechange = -not [string]::IsNullOrWhiteSpace($drivetarget)
$loadsnapshotdata = -not [string]::IsNullOrWhiteSpace($loadsnapshot)

$detection_list = New-Object -TypeName "System.Collections.ArrayList"