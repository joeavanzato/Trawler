<#
	.SYNOPSIS
		trawler helps Incident Responders discover suspicious persistence mechanisms on Windows devices.
	
	.DESCRIPTION
		trawler inspects a wide variety of Windows artifacts to help discover signs of persistence including the registry, scheduled tasks, services, startup items, etc.
        For a full list of inspected artifacts and MITRE Techniques, please see github.com/joeavanzato/trawler

	.PARAMETER OutputLocation
		The fully-qualified file-path where detection output should be stored (defaults to $PSScriptRoot, the same location the script is executing from)

    .PARAMETER snapshot
		If specified, tells trawler to load the designated file as an allow-list (defaults to $PSScriptRoot, the same location the script is executing from)

    .PARAMETER quiet
		If specified, tells trawler to suppress detection output to console

    .PARAMETER evtx
		If specified, tells trawler to log detections as JSON blobs to the specified Event Log (defaults to Log=Application, Source=trawler)

    .PARAMETER daysago
		If specified, tells trawler how far back (in days) to consider for suppressing time-based detections (defaults to 45 days - for detections that involve time such as "recently created", this will serve as the threshold).

	.PARAMETER ScanOptions
		Set to pick specific scanners to run. Multiple can be used when separated by a comma. (Supports tab completion)

	.PARAMETER HashMode
		Tells trawler which hashing algorithm to use for detection metadata - SHA1, SHA256 or MD5

	.PARAMETER drivetarget
		Tells trawler to target a separate drive rather than the local system.

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
		HelpMessage = 'The directory where Trawler output will be saved, defaults to the location where the script ran from')]
	[string]
	$OutputLocation = $PSScriptRoot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Which hashing algorithm to use. Defaults to SHA1')]
	[ValidateSet("SHA1", "SHA256", "MD5")]
	$HashMode = "SHA1",
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Suppress Detection Output to Console')]
	[switch]
	$Quiet,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Enable EventLog output - trawler will write detections to the Application EventLog under Source=trawler with EventID=9001 - events will be written in JSON format.  Must be running as administrator to create the Event Log source initially.')]
	[switch]
	$evtx,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path of the snapshot to use for comparison - this should be a JSON file from a previous trawler execution')]
	[string]
	$snapshot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The drive to target for analysis - for example, if mounting an imaged system as a second drive on an analysis device, specify via -drivetarget "D:" (PARTIALLY IMPLEMENTED)')]
	[string]
	$drivetarget,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'How many days back to search when doing time-based detections')]
	[int]
	$daysago = 45,
	[Parameter(
		Mandatory = $false,
		HelpMessage = "Allows for performing certain checks and ignoring others. Leave blank to execute all Persistence checks (or use 'All')")]
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
		"DirectoryServicesRestoreMode",
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
        "InstalledSoftware",
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
        "OfficeTrustedDocuments",
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
        "ServiceControlManagerSD",
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
		"Wow64LayerAbuse",
        "WSL"
	)]
	$ScanOptions = "All"
)

# Used for tracking snapshot effectiveness
$script:suppressed_detections = 0

# Used in detections when checking if a particular date is older/younger than the max-lookback date (threshold_date)
$threshold_date = (Get-Date).adddays(-$daysago)
# Event Log source used for creation/writing
$evtx_source = "trawler"
$evtx_logname = "Application"
# Control Flow Variables
$loadsnapshotdata = $PSBoundParameters.ContainsKey('snapshot')
$drivechange = $PSBoundParameters.ContainsKey('drivetarget')

# Variables used for augmenting detections throughout the script
$suspicious_process_paths = @(
	".*\\users\\(administrator|default|public|guest)\\.*",
	".*\\windows\\(debug|fonts|media|repair|servicing|temp)\\.*",
	".*recycle\.bin.*"
)
$suspicious_extensions = @('*.exe', '*.bat', '*.ps1', '*.hta', '*.vb', '*.vba', '*.vbs','*.rar', '*.zip', '*.gz', '*.7z', '*.dll', '*.scr', '*.cmd', '*.com', '*.ws', '*.wsf', '*.scf', '*.scr', '*.pif', '*.dmp','*.htm', '*.doc*','*.xls*','*.ppt*')
$suspicious_terms = ".*(\[System\.Reflection\.Assembly\]|regedit|invoke-iex|frombase64|tobase64|rundll32|http:|https:|system\.net\.webclient|downloadfile|downloadstring|bitstransfer|system\.net\.sockets|tcpclient|xmlhttp|AssemblyBuilderAccess|shellcode|rc4bytestream|disablerealtimemonitoring|wmiobject|wmimethod|remotewmi|wmic|gzipstream|::decompress|io\.compression|write-zip|encodedcommand|wscript\.shell|MSXML2\.XMLHTTP|System\.Reflection\.Emit\.AssemblyBuilderAccess|System\.Runtime\.InteropServices\.MarshalAsAttribute|memorystream|SuspendThread|EncodedCommand|MiniDump|lsass\.exe|Invoke-DllInjection|Invoke-Shellcode|Invoke-WmiCommand|Get-GPPPassword|Get-Keystrokes|Get-TimedScreenshot|Get-VaultCredential|Invoke-CredentialInjection|Invoke-Mimikatz|Invoke-NinjaCopy|Invoke-TokenManipulation|Out-Minidump|VolumeShadowCopyTools|Invoke-ReflectivePEInjection|Invoke-UserHunter|Invoke-ACLScanner|Invoke-DowngradeAccount|Get-ServiceUnquoted|Get-ServiceFilePermission|Get-ServicePermission|Invoke-ServiceAbuse|Install-ServiceBinary|Get-RegAutoLogon|Get-VulnAutoRun|Get-VulnSchTask|Get-UnattendedInstallFile|Get-ApplicationHost|Get-RegAlwaysInstallElevated|Get-Unconstrained|Add-RegBackdoor|Add-ScrnSaveBackdoor|Gupt-Backdoor|Invoke-ADSBackdoor|Enabled-DuplicateToken|Invoke-PsUaCme|Remove-Update|Check-VM|Get-LSASecret|Get-PassHashes|Show-TargetScreen|Port-Scan|Invoke-PoshRatHttp|Invoke-PowerShellTCP|Invoke-PowerShellWMI|Add-Exfiltration|Add-Persistence|Do-Exfiltration|Start-CaptureServer|Get-ChromeDump|Get-ClipboardContents|Get-FoxDump|Get-IndexedItem|Get-Screenshot|Invoke-Inveigh|Invoke-NetRipper|Invoke-EgressCheck|Invoke-PostExfil|Invoke-PSInject|Invoke-RunAs|MailRaider|New-HoneyHash|Set-MacAttribute|Invoke-DCSync|Invoke-PowerDump|Exploit-Jboss|Invoke-ThunderStruck|Invoke-VoiceTroll|Set-Wallpaper|Invoke-InveighRelay|Invoke-PsExec|Invoke-SSHCommand|Get-SecurityPackages|Install-SSP|Invoke-BackdoorLNK|PowerBreach|Get-SiteListPassword|Get-System|Invoke-BypassUAC|Invoke-Tater|Invoke-WScriptBypassUAC|PowerUp|PowerView|Get-RickAstley|Find-Fruit|HTTP-Login|Find-TrustedDocuments|Invoke-Paranoia|Invoke-WinEnum|Invoke-ARPScan|Invoke-PortScan|Invoke-ReverseDNSLookup|Invoke-SMBScanner|Invoke-Mimikittenz|Invoke-SessionGopher|Invoke-AllChecks|Start-Dnscat|Invoke-KrbRelayUp|Invoke-Rubeus|Invoke-Pandemonium|Invoke-Mongoose|Invoke-NETMongoose|Invoke-SecretsDump|Invoke-NTDS|Invoke-SharpRDP|Invoke-Kirby|Invoke-SessionHunter|Invoke-PrintNightmare|Invoke-Monkey365|Invoke-AzureHound|Kerberoast|Bloodhound|Sharphound|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableScriptScanning|DisableBlockAtFirstSeen|ExclusionPath).*"
$ipv4_pattern = '.*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*'
$ipv6_pattern = '.*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*'
$office_addin_extensions = ".wll",".xll",".ppam",".ppa",".dll",".vsto",".vba", ".xlam", ".com", ".xla"
$rat_terms = @(
    #Remote Access Tool Indicators
    # Any Process Name, Scheduled Task or Service containing these keywords will be flagged.
    "aeroadmin"
    "action1"
    "ammyadmin"
    "aa_v"
    "anydesk"
    "anyscreen"
    "anyviewer"
    "atera"
    "aweray_remote"
    "awrem32"
    "awhost32"
    "beyondtrust"
    "bomgar"
    "connectwise"
    "cservice"
    "dameware"
    "desktopnow"
    "distant-desktop"
    "dwservice"
    "dwagent"
    "dwagsvc"
    "dwrcs"
    "famitrfc"
    "g2comm"
    "g2host"
    "g2fileh"
    "g2mainh"
    "g2printh"
    "g2svc"
    "g2tray"
    "gopcsrv"
    "getscreen"
    "iperius"
    "kaseya"
    "litemanager"
    "logmein"
    "lmiignition"
    "lmiguardiansvc"
    "meshagent"
    "mstsc"
    "ninja1"
    "ninjaone"
    "PCMonitorManager"
    "pcmonitorsrv"
    "pulseway"
    "quickassist"
    "radmin"
    "rcclient"
    "realvnc"
    "remotepc"
    "remotetopc"
    "remote utilities"
    "RepairTech"
    "ROMServer"
    "ROMFUSClient"
    "rutserv"
    "screenconnect"
    "screenmeet"
    "showmypc"
    "smpcsetup"
    "strwinclt"
    "supremo"
    "sightcall"
    "splashtop"
    "surfly"
    "syncro"
    "tacticalrmm"
    "teamviewer"
    "tightvnc"
    "ultraviewer"
    "vnc"
    "winvnc"
    "vncviewer"
    "winvncsc"
    "winwvc"
    "xmreality"
    "ultravnc"
    "Zaservice"
    "Zohours"
    "ZohoMeeting"
    "zoho"
    "rpcgrab"
    "rpcsetup"
    "action1_agent"
    "aeroadmin"
    "alitask"
    "alpemix"
    "ammyy_admin"
    "anydesk"
    "apc_host"
    "ateraagent"
    "syncrosetup"
    "auvik.agent"
    "auvik.engine"
    "beamyourscreen"
    "beamyourscreen-host"
    "basupsrvc"
    "basupsrvcupdate"
    "basuptshelper"
    "bomgar-scc"
    "CagService"
    "ctiserv"
    "remote_host"
    "cloudflared"
    "connectwisechat-customer"
    "connectwisecontrol"
    "itsmagent"
    "rviewer"
    "crossloopservice"
    "pcivideo"
    "supporttool"
    "dntus"
    "dwrcs"
    "domotz_bash"
    "echoserver"
    "echoware"
    "ehorus standalone"
    "remoteconsole"
    "accessserver"
    "ericomconnnectconfigurationtool"
    "era"
    "ezhelp"
    "eratool"
    "ezhelpclient"
    "ezhelpclientmanager"
    "fastclient"
    "fastmaster"
    "fixmeitclient"
    "fleetdeck_agent_svc"
    "gp3"
    "gp4"
    "gp5"
    "getscreen"
    "g2a"
    "gotoassist"
    "gotohttp"
    "g2file"
    "g2quick"
    "g2svc"
    "g2tray"
    "goverrmc"
    "govsrv"
    "guacd"
    "helpbeam"
    "iit"
    "intouch"
    "hsloader"
    "ihcserver"
    "instanthousecall"
    "iadmin"
    "intelliadmin"
    "iperius"
    "iperiusremote"
    "ITSMAgent"
    "ItsmRsp"
    "ITSMService"
    "RDesktop"
    "RHost"
    "RmmService"
    "islalwaysonmonitor"
    "isllight"
    "isllightservice"
    "jumpclient"
    "jumpdesktop"
    "jumpservice"
    "agentmon"
    "ltsvc"
    "ltsvcmon"
    "lttray"
    "issuser"
    "landeskagentbootstrap"
    "ldinv32"
    "ldsensors"
    "laplink"
    "laplinkeverywhere"
    "llrcservice"
    "serverproxyservice"
    "laplink"
    "tsircusr"
    "romfusclient"
    "romserver"
    "romviewer"
    "lmiguardiansvc"
    "lmiignition"
    "logmein"
    "logmeinsystray"
    "support-logmeinrescue"
    "lmi_rescue"
    "mesh"
    "mikogo"
    "mikogolauncher"
    "mikogo-service"
    "mikogo-starter"
    "mionet"
    "mionetmanager"
    "myivomanager"
    "myivomgr"
    "nhostsvc"
    "nhstw32"
    "nldrw32"
    "rmserverconsolemediator"
    "client32"
    "pcictlui"
    "neturo"
    "ntrntservice"
    "netviewer"
    "ngrok"
    "ninjarmmagent"
    "nomachine"
    "nxd"
    "nateon"
    "nateon"
    "nateonmain"
    "ocsinventory"
    "ocsservice"
    "prl_deskctl_agent"
    "prl_deskctl_wizard"
    "prl_pm_service"
    "awhost32"
    "pcaquickconnect"
    "winaw32"
    "mwcliun"
    "pcnmgr"
    "webexpcnow"
    "pcvisit"
    "pcvisit_client"
    "pcvisit-easysupport"
    "pocketcontroller"
    "pocketcloudservice"
    "wysebrowser"
    "qq"
    "qqpcmgr"
    "konea"
    "quickassist"
    "radmin"
    "tdp2tcp"
    "rdp2tcp.py"
    "remobo"
    "remobo_client"
    "remobo_tracker"
    "rfusclient"
    "rutserv"
    "rutserv"
    "rutview"
    "rcengmgru"
    "rcmgrsvc"
    "remotesupportplayeru"
    "rxstartsupport"
    "remotepass-access"
    "rpaccess"
    "rpwhostscr"
    "remotepcservice"
    "rpcsuite"
    "remoteview"
    "rvagent"
    "rvagtray"
    "wisshell"
    "wmc"
    "wmc_deployer"
    "wmcsvc"
    "royalts"
    "rudesktop"
    "rustdesk"
    "screenconnect"
    "screenconnect.windowsclient"
    "seetrolcenter"
    "seetrolclient"
    "seetrolmyservice"
    "seetrolremote"
    "seetrolsetting"
    "showmypc"
    "simplehelpcustomer"
    "simpleservice"
    "windowslauncher"
    "remote access"
    "simplegatewayservice"
    "clientmrinit"
    "mgntsvc"
    "routernt"
    "sragent"
    "srmanager"
    "srserver"
    "srservice"
    "supremo"
    "supremohelper"
    "supremoservice"
    "supremosystem"
    "tacticalrmm"
    "teamviewer"
    "teamviewer_service"
    "teamviewerqs"
    "tv_w32"
    "tv_w64"
    "pstlaunch"
    "ptdskclient"
    "ptdskhost"
    "todesk"
    "pcstarter"
    "turbomeeting"
    "turbomeetingstarter"
    "ultraviewer"
    "ultraviewer_desktop"
    "ultraviewer_service"
    "vncserver"
    "vncserverui"
    "vncviewer"
    "winvnc"
    "webrdp"
    "weezo"
    "weezohttpd"
    "xeox-agent_x64"
    "za_connect"
    "zaservice"
    "zohotray"
)
# https://github.com/magicsword-io/LOLRMM/tree/main/yaml
$suspicious_software = @(
    ".*ithelp.*"
    ".*access.*"
    ".*absolute.*"
    ".*acronic.*"
    ".*remotix.*"
    ".*action1.*"
    ".*addigy.*"
    ".*adobe connect.*"
    ".*aeroadmin.*"
    ".*aliwangwang.*"
    ".*alpemix.*"
    ".*ammyy.*"
    ".*anydesk.*"
    ".*anyplace.*"
    ".*anyview.*"
    ".*apple remote.*"
    ".*atera.*"
    ".*auvik.*"
    ".*aweray.*"
    ".*barracuda.*"
    ".*basecamp.*"
    ".*beamyourscreen.*"
    ".*beanywhere.*"
    ".*beinsync.*"
    ".*beyondtrust.*"
    ".*bitvise.*"
    ".*bomgar.*"
    ".*carotdav.*"
    ".*centrastage.*"
    ".*datto.*"
    ".*centurion.*"
    ".*chicken.*"
    ".*chrome remote.*"
    ".*cloudflare tunnel.*"
    ".*cloudflared.*"
    ".*comodo.*"
    ".*connectwise.*"
    ".*crossloop.*"
    ".*crosstec.*"
    ".*cruzcontrol.*"
    ".*dameware.*"
    ".*deskday.*"
    ".*desknets.*"
    ".*deskshare.*"
    ".*desktopnow.*"
    ".*tunnels.*"
    ".*devolutions.*"
    ".*distant desktop.*"
    ".*domotz.*"
    ".*dragondisk.*"
    ".*duplicati.*"
    ".*dw service.*"
    ".*echoware.*"
    ".*ehorus.*"
    ".*kaseya.*"
    ".*emco remote.*"
    ".*encapto.*"
    ".*ericom.*"
    ".*accessnow.*"
    ".*remote.*"
    ".*extraputty.*"
    ".*ezhelp.*"
    ".*fastviewer.*"
    ".*fixme.*"
    ".*filezilla.*"
    ".*fleetdeck.*"
    ".*fortra.*"
    ".*free ping.*"
    ".*freenx.*"
    ".*freerdp.*"
    ".*gatherplace.*"
    ".*getscreen.*"
    ".*goto opener.*"
    ".*gotoassist.*"
    ".*gotohttp.*"
    ".*gotomypc.*"
    ".*guacamole.*"
    ".*goverlan.*"
    ".*helpbeam.*"
    ".*helpu.*"
    ".*intouch.*"
    ".*imperoconnect.*"
    ".*housecall.*"
    ".*insync.*"
    ".*intelliadmin.*"
    ".*iperius.*"
    ".*isl online.*"
    ".*isl light.*"
    ".*islonline.*"
    ".*itarian.*"
    ".*itsupport.*"
    ".*ivanti.*"
    ".*fastvnc.*"
    ".*jump cloud.*"
    ".*jump desktop.*"
    ".*kabuto.*"
    ".*khelpdesk.*"
    ".*kickidler.*"
    ".*kitty.*"
    ".*koofr.*"
    ".*labteach.*"
    ".*labtech.*"
    ".*landesk.*"
    ".*laplink.*"
    ".*level\.io.*"
    ".*level.*"
    ".*levelio.*"
    ".*lite manager.*"
    ".*litemanager.*"
    ".*logmein.*"
    ".*manage engine.*"
    ".*manageengine.*"
    ".*megasync.*"
    ".*meshcentral.*"
    ".*quick assist.*"
    ".*mikogo.*"
    ".*mionet.*"
    ".*mobaxterm.*"
    ".*mocha vnc.*"
    ".*mremote.*"
    ".*msp360.*"
    ".*multicloud.*"
    ".*mygreenpc.*"
    ".*myivo.*"
    ".*n-able.*"
    ".*nateon.*"
    ".*naverisk.*"
    ".*netop.*"
    ".*netreo.*"
    ".*netsupport.*"
    ".*neturo.*"
    ".*netviewer.*"
    ".*ngrok.*"
    ".*ninjaone.*"
    ".*ninjarmm.*"
    ".*nomachine.*"
    ".*nordlocker.*"
    ".*noteon.*"
    ".*ntr remote.*"
    ".*ocs inventory.*"
    ".*onionshare.*"
    ".*optitune.*"
    ".*pandora rc.*"
    ".*panorama9.*"
    ".*parallels.*"
    ".*pcanywhere.*"
    ".*pcnow.*"
    ".*pcvisit.*"
    ".*pdq connect.*"
    ".*pilixo.*"
    ".*pocket cloud.*"
    ".*pocket controller.*"
    ".*psexec.*"
    ".*pulseway.*"
    ".*putty.*"
    ".*remote assistance.*"
    ".*quest kace.*"
    ".*quickassist.*"
    ".*radmin.*"
    ".*rdp2tcp.*"
    ".*rdpview.*"
    ".*rdpwrap.*"
    ".*realvnc.*"
    ".*remcos.*"
    ".*remmina.*"
    ".*remobo.*"
    ".*remote\.it.*"
    ".*devolutions.*"
    ".*remote desktop.*"
    ".*remote manipulator.*"
    ".*remote utilities.*"
    ".*remotecall.*"
    ".*remotepc.*"
    ".*remotepass.*"
    ".*remoteview.*"
    ".*res automation.*"
    ".*rocketremote.*"
    ".*royal apps.*"
    ".*rport.*"
    ".*rudesktop.*"
    ".*runsmart.*"
    ".*rustdesk.*"
    ".*s3 browser.*"
    ".*screenconnect.*"
    ".*screenmeet.*"
    ".*securecrt.*"
    ".*seetrol.*"
    ".*senso cloud.*"
    ".*servereye.*"
    ".*showmypc.*"
    ".*simplehelp.*"
    ".*site24.*"
    ".*skyfex.*"
    ".*web vnc.*"
    ".*smartftp.*"
    ".*smartty.*"
    ".*sorillus.*"
    ".*splashtop.*"
    ".*spyanywhere.*"
    ".*sunlogin.*"
    ".*superops.*"
    ".*supremo.*"
    ".*syncro.*"
    ".*syncthing.*"
    ".*synergy.*"
    ".*sysaid.*"
    ".*syspectr.*"
    ".*tactical rmm.*"
    ".*tailscale.*"
    ".*teamviewer.*"
    ".*teledesktop.*"
    ".*tigervnc.*"
    ".*tightvnc.*"
    ".*todesk.*"
    ".*turbomeeting.*"
    ".*ultra vnc.*"
    ".*ultraviewer.*"
    ".*ultravnc.*"
    ".*webrdp.*"
    ".*weezo.*"
    ".*winscp.*"
    ".*x2go.*"
    ".*xeox.*"
    ".*xpra.*"
    ".*xrdp.*"
    ".*xshell.*"
    ".*yandex.*"
    ".*zabbix.*"
    ".*zerotier.*"
    ".*zoc.*"
    ".*zohoassist.*"
)

# Script level container for detections
$detection_list = New-Object -TypeName "System.Collections.ArrayList"
$detection_hash_array_snapshot = New-Object System.Collections.Generic.List[System.Object]
$new_psdrives_list = @{}