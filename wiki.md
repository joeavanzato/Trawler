This page focuses on providing useful links and information regarding each possible detection present in trawler to speed up analysis and answer common questions.

# Detection Topics
* [Scheduled Tasks](#scheduled-tasks)
* [Users](#users)
* [Services](#services)
* [Running Processes](#running-processes)
* [Network Connections](#network-connections)
* [WMI Event Consumers](#wmi-event-consumers)
* [Startup Items](#startup-items)
* [BITS Jobs](#bits-jobs)
* [Windows Accessibility Features](#windows-accessibility-features)
* [PowerShell Profiles](#powershell-profiles)
* [Office Startup Addins](#office-startup-addins)
* [SilentProcessExit Monitoring](#silentprocessexit-monitoring)
* [Winlogon Helper DLL Hijacking](#winlogon-helper-dll)
* [Image File Execution Option Hijacking](#image-file-execution-option)
* [RDP Shadowing](#rdp-shadowing)
* [Remote UAC Settings](#remote-uac-settings)
* [Print Monitor DLLs](#print-monitor-dlls)
* [LSA Security/Authentication Packages](#lsa-securityauthentication-packages)
* [Time Provider DLLs](#time-provider-dlls)
* [Print Processor DLLs](#print-processor-dlls)
* [Boot/Logon Active Setup](#bootlogon-active-setup)
* [User Initialization Logon Scripts](#user-initialization-logon-scripts)
* [ScreenSaver Executable](#screensaver-executable)
* [Netsh DLLs](#netsh-dlls)
* [AppCert DLLs](#appcert-dlls)
* [AppInit DLLs](#appinit-dlls)
* [Application Shimming](#application-shimming)
* [COM Objects](#com-objects)
* [LSA Notification](#lsa-notification)
* ['Office test' Usage](#office-test-usage)
* [Office GlobalDotName Usage](#office-globaldotname-usage)
* [Terminal Services / Autodial DLL](#terminal-services--autodial-dll)
* [Command AutoRun Processor Abuse](#command-autorun-processor-abuse)
* [Outlook OTM](#outlook-otm)
* [Trust Provider Hijacking](#trust-providers)
* [LNK Target Scanning (Suspicious Terms, Multiple Extensions, Multiple EXEs)](#lnk-targets)
* [Commonly-Masqueraded Windows DLL Names in running process (eg. un-signed WptsExtensions.dll)](#windows-phantom-dlls)
* [Scanning Critical OS Directories for Unsigned EXEs/DLLs](#unsigned-exedll-in-critical-locations)
* [Un-Quoted Service Path Hijacking](#service-paths)
* [PATH Binary Hijacking](#path-os-binary-hijacks)
* [Common File Association Hijacks and Suspicious Keywords](#file-association-hijacks)
* [Suspicious Certificate Hunting](#installed-certificates)
* [GPO Script Discovery/Scanning](#gpo-scripts)
* [NLP Development Platform DLL Overrides](#nlp-development-platform-dll-overrides)
* [AeDebug/.NET/Script/Process/WER Debug Replacements](#aedebug/.net/script/process/wer-debug-replacements)
* [Explorer 'Load'](#Explorer-'Load')
* [Windows Terminal startOnUserLogin Hijacks](#Windows-Terminal-startOnUserLogin-Hijacks)
* [App Path Mismatches](#App-Path-Mismatches)
* [Service DLL/ImagePath Mismatches](#Service-DLL/ImagePath-Mismatches)
* [GPO Extension DLLs](#GPO-Extension-DLLs)
* [Potential COM Hijacks](#Potential-COM-Hijacks)
* [Non-Standard LSA Extensions](#Non-Standard-LSA-Extensions)
* [DNSServerLevelPluginDll Presence](#DNSServerLevelPluginDll-Presence)
* [Explorer\MyComputer Utility Hijack](#Explorer\MyComputer-Utility-Hijack)
* [Terminal Services InitialProgram Check](#Terminal-Services-InitialProgram-Check)
* [RDP Startup Programs](#RDP-Startup-Programs)
* [Microsoft Telemetry Commands](#Microsoft-Telemetry-Commands)
* [Non-Standard AMSI Providers](#Non-Standard-AMSI-Providers)
* [Internet Settings LUI Error DLL](#Internet-Settings-LUI-Error-DLL)
* [PeerDist\Extension DLL](#PeerDist\Extension-DLL)
* [ErrorHandler.CMD Checks](#ErrorHandler.CMD-Checks)
* [Built-In Diagnostics DLL](#Built-In-Diagnostics-DLL)
* [MiniDumpAuxiliary DLLs](#MiniDumpAuxiliary-DLLs)
* [KnownManagedDebugger DLLs](#KnownManagedDebugger-DLLs)
* [WOW64 Compatibility Layer DLLs](#WOW64-Compatibility-Layer-DLLs)
* [EventViewer MSC Hijack](#EventViewer-MSC-Hijack)
* [Uninstall Strings Scan](#Uninstall-Strings-Scan)
* [PolicyManager DLLs](#PolicyManager-DLLs)
* [SEMgr Wallet DLL](#SEMgr-Wallet-DLL)
* [WER Runtime Exception Handlers](#WER-Runtime-Exception-Handlers)
* [HTML Help (.CHM)](#HTML-Help-(.CHM))
* [Remote Access Tool Artifacts (Files, Directories, Registry Keys)](#Remote-Access-Tool-Artifacts-(Files,-Directories,-Registry-Keys))
* [ContextMenuHandler DLL Checks](#ContextMenuHandler-DLL-Checks)
* [Office AI.exe Presence](#Office-AI.exe-Presence)
* [Notepad++ Plugins](#Notepad++-Plugins)
* [MSDTC Registry Hijacks](#MSDTC-Registry-Hijacks)
* [Narrator DLL Hijack (MSTTSLocEnUS.DLL)](#Narrator-DLL-Hijack-(MSTTSLocEnUS.DLL))
* [Suspicious File Location Checks](#Suspicious-File-Location-Checks)
* [BootVerificationProgram Check](#BootVerificationProgram-Check)
* [DiskCleanupHandler Checks](#DiskCleanupHandler-Checks)
* [Low Integrity Isolation Checks](#Low-Integrity-Isolation-Checks)


## Scheduled Tasks
Trawler performs multiple detections when examining Scheduled Tasks, listed below;
* [Non-Standard Scheduled Task running as SYSTEM](#non-standard-scheduled-task-running-as-system)
* [Scheduled Task contains an IP Address](#scheduled-task-contains-an-ip-address)
* [Scheduled Task contains suspicious keywords](#scheduled-task-contains-suspicious-keywords)
* [User-Created Task running as SYSTEM](#user-created-task-running-as-system)
* [User Created Task](#user-created-task)
* [Non-Standard Scheduled Task Executable](#non-standard-scheduled-task-executable)

Each of these is intended to cover a specific use-case and provide clear information to analysts to help focus efforts.  These are broken out below.

### Non-Standard Scheduled Task running as SYSTEM
This detection indicates that a scheduled task which is not stored in trawler's allow-list is currently setup to run as SYSTEM, the highest privilege on a Windows computer.  This does not mean that the task is inherently malicious - trawler's allow-list is constantly growing but is not all-inclusive of all possible Microsoft tasks and additionally, many legitimate third-party tasks run as SYSTEM by design.  This is meant to highlight **possible** threats to the system - further analysis should be performed to determine whether the task is legitimate or not.

### Scheduled Task contains an IP Address
This detection indicates that a scheduled task argument path matched regex patterns for either an IPv4 or IPv6 address - it is possible for false positives to occur should naming conventions for versions or other identifiers match these patterns.  The task arguments and path should be examined to determine whether this is a true-positive or false-positive - malware often includes C2 IP addresses as arguments when installing persistence mechanisms.  

### Scheduled Task contains suspicious keywords
This detection indicates that the scheduled task executable path/argument contains at least one 'suspicious' keyword - the list of keywords includes mostly terms that are often associated with various 'one-liner' style persistence techniques such as 'System.Net.Reflection', 'downloadstring', 'frombase64', etc.  The task should be analyzed to ensure it is legitimate.

### User-Created Task running as SYSTEM
This detection indicates that a task which appears to have been directly created by a user (rather than a corporation such as Microsoft, Google, etc) is running with SYSTEM level privileges.  Malicious tasks will often trigger this due to typically being created by a local or domain user and running with high privileges.

### User Created Task
This detection indicates that a task which appears to have been directly created by a user (rather than a corporation such as Microsoft, Google, etc) - these tasks should be inspected to ensure they are legitimate.

### Non-Standard Scheduled Task Executable
This detection is the lowest priority Scheduled Task executable and merely indicates that the alerted task is not present in the trawler allow-list.  The allow-list was initially assembled by examining all 'default' scheduled tasks which occur on Windows 10, 2016, 2019 and 2022 - it is constantly being expanded with 'known-good' items that are part of the Windows OS.  Most third-party software that utilizes a scheduled task will trigger this detection.

## Users
Currently, trawler gathers are local administrators and generates an alert for each one - threat actors often create local administrative accounts for persistence and each account should be reviewed to ensure it is legitimate.

## Services
Similarly to Scheduled Tasks, trawler executes multiple pieces of detection logic when examining Windows Services, listed below;
* [Non-Standard Service Path](#non-standard-service-path)
* [Service launching from cmd.exe](#service-launching-from-cmdexe)
* [Service launching from powershell.exe](#service-launching-from-powershellexe)
* [Service contains known-RAT keyword](#service-contains-known-rat-Keyword)

### Non-Standard Service Path
Like Scheduled Tasks, trawler maintains an allow-list of common Windows Services and alerts when a 'non-standard' service is detected - this can be very common depending on the amount of third-party applications deployed on the system.  Each service should be inspected to ensure it is legitimate.

### Service launching from cmd.exe
This detection indicates that an installed service is directly using cmd.exe rather than a native service binary - this is uncommon for legitimate applications but often used by malware.

### Service launching from powershell.exe
This detection indicates that an installed service is directly using powershell.exe rather than a native service binary - this is uncommon for legitimate applications but often used by malware.

### Service contains known-RAT Keyword
This detection indicates that the service path and arguments contain a keyword often associated with Remote Access Control tools.  A list of these keywords is used to check against with RegEx - if the term appears anywhere in the Service command-line, an alert is triggered.

## Running Processes
trawler will scan all running processes for a few common IOCs which may indicate some form of abuse.

### Running Process has known-RAT Keyword
trawler uses regex to check the commmandline of all active processes against a list of Remote Access Tool (RAT) keywords to see if there is a match.

### IP Address Pattern detected in Process CommandLine
trawler uses regex to check the commandline of all active processes against IPv4 and IPv6 regex patterns to determine if the commandline contains an IP address - which often is the case for reverse-tunnel or remote access tool software.

### Suspicious Executable Path on Running Process
trawler uses regex to check whether the executable for each running process is operating from a 'suspicious' path such as \users\administrator, \users\public or \windows\temp.

## Network Connections
trawler checks each active TCP connection for common signs of abuse to help defenders identify suspicious connections.

### Process Listening on Ephemeral Port
trawler checks for any processes which have an actively listening TCP connection on an ephemeral port - this can include lots of false positives.

### Established Connection on Suspicious Port
trawler checks for any process which has an established TCP connection on a list of suspicious ports such as 20, 21, 22, 23, 25, 137, 138, 445, 3389 and 443.

### Process running from suspicious path has Network Connection
trawler does a final check for any process running from a suspicious path which has a TCP port open in any state.

## WMI Event Consumers
trawler performs checks to hunt for WMI Consumers which have been setup on the system - often as a means of persistence since most normal users do not employ these techniques.

### WMI ActiveScript Consumer
trawler will alert when any ActiveScript based consumer is detected - these consumers will trigger a script when the relevant event occurs.

### WMI CommandLine Consumer
trawler will also alert when any CommandLine consumer is detected - these consumers will trigger the listed commandline when the relevant event occurs.

## Startup Items
In this section, trawler will check all items returned by Win32_StartupCommand as well as the common Run/RunOnce/RunEx/RunOnceEx/RunServices for all HKLM/HKCU hives for any entry.

### Startup Item Review
There is no filtering done on these basic startup items - each item should be reviewed to ensure legitimacy.

## BITS Jobs
trawler will check for any active BITS Job and the associated commandline to help analysts detect suspicious persistence.

### BITS Item Review
No filtering is done on results returned by these queries - all items should be reviewed for legitimacy.

## Windows Accessibility Features
trawler will first check files that are commonly modified by adversaries to help achieve persistence on Windows - these include the following:
* AtBroker.exe
* DisplaySwitch.exe
* Magnify.exe
* Narrator.exe
* osk.exe
* sethc.exe
* utilman.exe
* HID.dll
If any of these files has a creation date that is not equal to the last modified data, trawler will alert.

### Potential modification of Windows Accessibility Feature
This alert indicates that one of the files above has a modification timestamp that does not match the creation timestamp - something that is typically uncommon in most Windows installations since these files do not typically receive updates.

## PowerShell Profiles
trawler will hunt for customized PowerShell profiles that exist on disk - it is possible for adversaries to abuse these for persistence and they should be reviewed to ensure tampering has not occurred.

### Review: Custom PowerShell Profile
No filtering is performed here - these should be reviewed to ensure they are legitimate.

### Review: Global Custom PowerShell Profile
No filtering is performed here - this indicates a PowerShell profile has been created that applies to all users - it should be reviewed for legitimacy.

## Office Startup Addins
trawler performs a variety of checks focused on Outlook/Word/Excel/etc Startup/Addins.

### Potential Persistence via Outlook Application Startup
This indicates a file was identified at a location such as AppData\Roaming\Microsoft\Outlook\VbaProject.OTM - this file should be reviewed to ensure it is legitimate.

### Non-Standard Office Trusted Location
This logic will scan the registry key located at HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations to identify locations which are 'non-standard' and potentially have been added by an adversary.

## SilentProcessExit Monitoring
trawler will scan for potential abuse of process exit monitoring by adversaries via checking HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit

### Process Launched on SilentProcessExit
This alert indicates that a process has been detected which will be launched upon the exiting of another specified process - this should be reviewed to ensure the use is legitimate.

## Winlogon Helper DLL
trawler will review all currently enabled Winlogon helper DLLs (HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon) to identify any non-standard executables.

### Potential WinLogon Helper Persistence
This detection indicates the presence of a non-standard Winlogon Helper DLL at the above registry path that will be executed when a user logs on to the system.

## Image File Execution Option
trawler will review keys at HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options to identify any programs which have a debugger executable setup to inject into the process at runtime.

### Potential Image File Execution Option Debugger Injection
This detection indicates that the listed program will have the listed debugger program injected at runtime.

## RDP Shadowing
trawler will scan the key located at HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services to determine the current status of RDP Shadow Consent - if enabled, this can allow the 'shadowing' of RDP sessions without user consent and may be used to steal information from unsuspecting users.

### RDP Shadowing without Consent is Enabled
This detection indicates that RDP Shadowing Consent is disabled - most often this is not the case for 'normal' environments.

## Remote UAC Settings
trawler will check whether or not UAC is enabled for remote sessions on the target computer (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) - disabling this can lead to easier privilege escalation for threat actors.

### UAC Disabled for Remote Sessions
This detection indicates UAC is disabled for remote sessions.

## Print Monitor DLLs
trawler will scan all currently enabled Print Monitor DLLs (HKLM\SYSTEM\$currentcontrolset\Control\Print\Monitors) to identify anomalous programs.

### Non-Standard Print Monitor DLL
This detection indicates a DLL was identified that is not part of the default Windows installation (APMon, AppMon, FXSMON, localspl, tcpmon, usbmon, WSDMon).

## LSA Security/Authentication Packages
trawler will review DLLs loaded in the context of the Local Security Authority (LSA) ($REG) to identify any anomalous programs being executed.

## Time Provider DLLs
trawler will review DLLs loaded by Microsoft as 'Time Provider' DLLs (HKLM\SYSTEM\$currentcontrolset\Services\W32Time\TimeProviders) to help identify any anomalous DLLs being loaded.

### Non-Standard Time Providers DLL
This detection will trigger when a Time Provider DLL is found that is not part of the default set included in Windows.

## Print Processor DLLs
trawler will scan DLLs loaded as 'Print Processor' DLLs ($REG) to help identify any anomalous programs being loaded.

## Boot/Logon Active Setup
trawler will scan programs launched during active setup processes ($REG) to help identify anomalous program startups.

## User Initialization Logon Scripts
trawler will scan logon scripts at $LOC to help identify anom

## ScreenSaver Executable
trawler will check for any executable setup to be run when the screensaver is invoked ($LOC)

## Netsh DLLs
trawler will check for any DLLs setup to be loaded in the context of netsh.exe at HKLM\SOFTWARE\Microsoft\Netsh.

## AppCert DLLs
trawler will check for any DLLs setup to be loaded under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ - these DLLs are loaded into almost every process on the system if they use common WINAPI calls such as CreateProcess, etc.

## AppInit DLLs
trawler will scan for anomalous AppInit DLLs - libraries which are loaded by user32.dll into all processes that load user32.dll (most processes/software) [https://attack.mitre.org/techniques/T1546/010/].

## Application Shimming
trawler will scan for anomalous application shims which can be used by attackers to hook/redirect code in a malicious manner [https://attack.mitre.org/techniques/T1546/011/].

## COM Objects
trawler will perform a COM object scan and attempt to identify anomalous COM object software [https://attack.mitre.org/techniques/T1546/015/] - trawler contains a large allow-list of known COM-object mappings obtained from Windows 10, Server 2012, Server 2016 and Server 2019.  These mappings are used as an allow-list when scanning a target registry hive - mismatches are alerted on as potential hijacks.  This is prone to false-positives.

## LSA Notification
trawler will scan specified notification DLLs for any non-standard entries at HKLM\SYSTEM\$currentcontrolset\Control\Lsa.

## 'Office test' Usage
trawler will check for the 'Office Test' [https://attack.mitre.org/techniques/T1137/002/] persistence mechanism by scanning the relevant registry keys and looking for any anomalous DLLs which, if specified, will be loaded when an Office application starts up.

## Office GlobalDotName Usage
trawler will hunt for the presence of an anomalous office template specified inside the 'GlobalDotName' key located at HKCU\software\microsoft\office\vv.v\word\options\GlobalDotName [https://cyberint.com/blog/research/office-templates-and-globaldotname-a-stealthy-office-persistence-technique/].

## Terminal Services / Autodial DLL
trawler will check for any non-standard autodial DLL loaded by the Winsock library at HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL.

## Command AutoRun Processor Abuse
trawler will scan for any non-default command processors setup at keys such as HKCU\Software\Microsoft\Command Processor - these can be abused to achieve code execution when a command is entered on the system.

## Outlook OTM 

## Trust Providers

## LNK Targets
trawler will scan recent .lnk files within each user profile directory to hunt for any potential abuse in the link target.

### LNK Target contains multiple executables
This detection will trigger if the link target seemingly contains reference to multiple executables.

### LNK Target contains suspicious key-term
This detection will trigger if the link target contains 1 or more suspicious terms, including items such as 'invoke-iex', 'frombase64', 'rundll32', etc.

### LNK Target contains multiple file extensions
This detection will trigger if the link target seemingly contains multiple extensions.

## Windows 'Phantom' DLLs
trawler will scan running processes to hunt for indicators that a 'phantom' DLL has been loaded by the process - this includes commonly-abused DLLs such as 'WptsExtensions.dll', 'fveapi.dll', 'phoneinfo.dll', etc.

### Suspicious DLL with commonly-masqueraded name loaded into running process.
This will trigger if one or more signed 'phantom' DLLs is loaded into a running process.

### Suspicious Unsigned DLL with commonly-masqueraded name loaded into running process.
This will trigger if one or more unsigned 'phantom' DLLs is loaded into a running process.

## Unsigned EXE/DLL in critical locations
trawler will scan critical system directories to hunt for any executable files which are not signed.

### Unsigned DLL/EXE present in critical OS directory
This detection will trigger if an unsigned executable is discovered in a critical system directory, including %WINDOWS%, %WINDOWS%\system32, %WINDOWS%\system and %WINDOWS%\temp.

## Service Paths
trawler will scan for unquoted service path hijack attempts that a threat actor may be attempting to abuse for privilege escalation and/or persistence.

## PATH OS Binary Hijacks
trawler will hunt for any potential PATH hijacks using system binary names - looking for any binary present in system32 that is also present in a PATH location prior to system32 - indicating a possible hijack of a named system binary.

### Possible PATH Binary Hijack - same name as SYS32 binary in earlier PATH entry
This detection indicates that a binary was identified having the same name as a file in system32 and existing in a prior PATH entry.  This is typically very uncommon.

## File Association Hijacks
trawler will review existing file associations using a small allow-list to hunt for anomalous entries and other suspicious associations.

## Installed Certificates
trawler will examine all installed certificates and perform a variety of checks looking for anomalous features, including listing all non-default certificates, validating root certificates and listing certificates that are from non-standard issuing authorities.

## GPO Scripts
trawler will scan any existing GPO scripts for user logon/logoff and computer startup/shutdown for suspicious key words that may indicate abuse of this mechanism for persistence or other adversary behavior.

## NLP Development Platform DLL Overrides
trawler will scan for any override DLLs specified in keys under HKLM\SYSTEM\CurrentControlSet\Control\ContentIndex\Language - these DLLs may be loaded by SearchIndexer.exe.

## AeDebug/.NET/Script/Process/WER Debug Replacements
trawler will check for non-standard DLLs specified at locations for multiple debuggers such as HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug and HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs.

## Explorer 'Load'

## Windows Terminal startOnUserLogin Hijacks
trawler will scan terminal logon profiles to identify any suspicious software that is setup to execute when a user logs on to the system remotely, typically located at C:\Users\_USER_\AppData\Local\Packages\Microsoft.WindowsTerminal*\LocalState\settings.json.

## App Path Mismatches
trawler will scan 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths' for any named executables that do not match the value specified in the 'Name' key - this can lead to possible privilege escalation or persistence by skilled attackers.

## Service DLL/ImagePath Mismatches
trawler will scan HKLM\SYSTEM\$currentcontrolset\Services and hunt for any mismatches between defined ImagePath and PathName values - it is possible for skilled attackers to manipulate registry values to substitute their own code instead of a legitimate service, leading to persistence and/or privilege escalation.

## GPO Extension DLLs
trawler will scan currently installed GPO extension DLLs specified at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions for any non-standard DLLs - these should be reviewed to ensure they are legitimate.

## Potential COM Hijacks
trawler will scan COM Objects in the registry to attempt to identify potential hijacks - this detection is prone to false positives due to many factors.  Trawler maintains a large allow-list for 'default' COM object mappings obtained from Windows 10, Server 2012, Server 2016 and Server 2019 - this helps reduce noise wherever possible but it is not perfect.  

## Non-Standard LSA Extensions
trawler will check for any non-standard DLLs loaded into lsass.exe under HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv.

## DNSServerLevelPluginDll Presence
trawler will check HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters for any non-standard DLL loaded by DNS activities when resolving unknown names.

## Explorer\MyComputer Utility Hijack


## Terminal Services InitialProgram Check

## RDP Startup Programs

## Microsoft Telemetry Commands


## Non-Standard AMSI Providers
trawler will check AMSI providers located at $LOC for any non-standard programs.

## Internet Settings LUI Error DLL
trawler will scan for any abnormal DLLs present under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\LUI, which normally contains a DLL used by wininet.dll.

## PeerDist\Extension DLL
trawler will scan for any non-standard DLL specified at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension - this DLL will be used during certain P2P functionality by wininet.dll.

## ErrorHandler.CMD Checks
trawler will check for the presence of %HOMEDRIVE%\windows\Setup\Scripts\ErrorHandler.cmd - this file may be executed during certain error handling automations within Windows.

## Built-In Diagnostics DLL
trawler will check for non-standard DLLs specified in paths such as HKLM\SOFTWARE\WOW6432Node\Microsoft\BidInterface\Loader - these DLLs will be loaded as part of ADO.NET Tracing Diagnostics.

## MiniDumpAuxiliary DLLs
trawler will check for any non-standard DLL specified at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\KnownManagedDebuggingDlls - these DLLs will be loaded inside of MiniDumpWriteDump when it finds a registerered auxiliaryy DLL for a module in the target process, of which there can be multiple.

## KnownManagedDebugger DLLs
trawler will check for any non-standard DLL specified at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls - these DLLs will be loaded inside of MiniDumpWriteDump when it finds a registerered auxiliaryy DLL for a module in the target process, of which there can be multiple.

## WOW64 Compatibility Layer DLLs
trawler will scan for any DLLs loaded under HKLM\SOFTWARE\Microsoft\Wow64\x86 for the purposes of assisting x86/x64 compatibility for legacy applications.

### Non-Standard Wow64\x86 DLL loaded into x86 process
This detection indicates trawler has identified a DLL that will be loaded by the system in the context of x86/x64 compatibility.  No filtering is done for this detection.

## EventViewer MSC Hijack
trawler will scan registry keys associated with the Microsoft Management Console to hunt for any signs of tampering in the redirection commandline/URL (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer).

### Event Viewer MSC Hijack
This detection indicates trawler has identified a non-standard value in a registry key associated with MSC redirection (value is not empty or equal to 'http://go.microsoft.com/fwlink/events.asp').

## Uninstall Strings Scan
When a program is uninstalled, it is possible to have a command run post-uninstall, as specified in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall - trawler will scan these strings for suspicious key terms.

### Uninstall String with Suspicious Keywords
This detection indicates trawler has identified an uninstall/quiet uninstall string that contains suspicious key terms.

## PolicyManager DLLs
trawler will scan for any non-standard DLLs specified for use in PolicyManager as located at HKLM\SOFTWARE\Microsoft\PolicyManager\default.

## SEMgr Wallet DLL
trawler will scan for any non-standard DLL specified at HKLM\Software\Microsoft\SEMgr\Wallet - this DLL will be called when a new Wallet is instantiated and GetMockWalletCOMInstance is exported by this wallet.

## WER Runtime Exception Handlers
trawler will scan for any non-standard exception handlers specified at HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules - these DLLs will be loaded when a process crashes to allow for the claimning of a crash as appropriate.

## HTML Help (.CHM)
trawler will scan the keys located at 'HKCU\Software\Microsoft\HtmlHelp Author' to identify any non-standard DLLs that will be loaded when a .chm file is executed.

## Remote Access Tool Artifacts (Files, Directories, Registry Keys)
trawler will scan the target drive for a variety of artifacts relating to different Remote Access Tools (RATs) - this includes the presence of certain files, directories and registry keys.

## ContextMenuHandler DLL Checks

## Office AI.exe Presence
trawler will check for the presence of "$HOMEDRIVE:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommon*\Microsoft Shared\OFFICE*\AI.exe" - an executable that will be launched automatically by certain Word related processes.  It is possible to replace this executable as a persistence mechanism as this file does not always exist and Word will always look for it.

## Notepad++ Plugins
trawler will check for all installed Notepad++ plugins and alert on any non-default DLLs - this does not mean they are inherently malicious.

## MSDTC Registry Hijacks
trawler will check the DLLs specified at HKLM\SOFTWARE\Microsoft\MSDTC\MTxOCI to look for any non-standard DLLs being loaded by MSDTC.

## Narrator DLL Hijack (MSTTSLocEnUS.DLL)
trawler will check to see if Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL is present - this DLL is loaded by Windows but is not present by default.

## Suspicious File Location Checks
trawler will scan Users\Public, Users\Administrator and Windows\temp for any suspicious file extensions in order to identify potential malware.

## BootVerificationProgram Check
trawler will check all currently setup BootVerificationPrograms at HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram - programs listed here will be launched as a service on computer startup.

## DiskCleanupHandler Checks
trawler will scan all registeres Disk Cleanup Handlers at HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches to find any non-default handlers installed on a system.

## Low Integrity Isolation Checks
trawler will scan all COM objects to identify any potential programs which are running without the default Low Integrity Isolation setting.  This is typically rare and may indicate abuse of that specific program by a threat actor to interact with the system at a higher privilege level than the default.