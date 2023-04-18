<p align="center">
<img src="logo.png" height="300">
</p>
<h1 align="center">
Dredging Windows for Persistence 
</h1>

## What is it?

Trawler is a PowerShell script designed to help Incident Responders discover potential indicators of compromise on Windows hosts, primarily focused on persistence mechanisms including Scheduled Tasks, Services, Registry Modifications, Startup Items, Binary Modifications and more.

Currently, trawler can detect most of the persistence techniques specifically called out by MITRE and Atomic Red Team with more detections being added on a regular basis.

## How do I use it?
Just download and run trawler.ps1 from an Administrative PowerShell/cmd prompt - any detections will be displayed in the console as well as written to a CSV ('detections.csv') in the current working directory.  The generated CSV will contain Detection Name, Source, Risk, Metadata and the relevant MITRE Technique.

Or use this one-liner from an Administrative PowerShell terminal:
```
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/joeavanzato/Trawler/main/trawler.ps1'))
```

Certain detections have allow-lists built-in to help remove noise from default Windows configurations (10/2016/2019/2022) - expected Scheduled Tasks, Services, etc.  Of course, it is always possible for attackers to hijack these directly and masquerade with great detail as a default OS process - take care to use multiple forms of analysis and detection when dealing with skillful adversaries.

If you have examples, write-ups or ideas for additional detections or allow-list items, please feel free to submit an Issue or PR with relevant technical details/references - the code-base is a little messy right now and will be cleaned up over time.

## Example Images
<p align="center">
<img src="sample.PNG">
</p>
<p align="center">
<img src="sample2.PNG">
</p>


## What is inspected?

* Scheduled Tasks
* Users
* Services
* Running Processes
* Network Connections
* WMI Event Consumers
* Startup Items
* BITS Jobs
* Windows Accessibility Modifications
* PowerShell Profile Existence
* Office Add-Ins/Startup Items
* SilentProcessExit Monitoring
* Winlogon Helper DLL Hijacking
* Image File Execution Option Hijacking
* RDP Shadowing
* UAC Setting for Remote Sessions
* Print Monitor DLL Hijacking
* LSA Security and Authentication Package Hijacking
* Time Provider DLL Hijacking
* Print Processor DLL Hijacking
* Boot/Logon Active Setup Hijacking
* User Initialization Logon Script Hijacking
* ScreenSaver Executable Hijacking
* Netsh DLL Hijacking
* AppCert DLL Hijacking
* AppInit DLL Hijacking
* Application Shimming
* COM Object Hijacking
* LSA Notification Hijacking
* 'Office test' Usage
* Office GlobalDotName Usage
* Terminal Services DLL Hijacking
* Autodial DLL Hijacking
* Command AutoRun Processor
* Outlook OTM Hijacking
* Trust Provider Hijacking
* LNK Target Scanning
* Commonly-Masqueraded Windows DLL Names in running process (eg. un-signed WptsExtensions.dll)
* Scanning Critical OS Directories for Unsigned EXEs/DLLs
* Un-Quoted Service Path Hijacking
* PATH Binary Hijacking

TODO
* Browser Extension Analysis
* File Association Hijacking
* Certificate Installation (https://www.ired.team/offensive-security/persistence/t1130-install-root-certificate)
* Maybe: Temporary RID Hijacking (https://www.ired.team/offensive-security/persistence/rid-hijacking)
* Improve Office Trusted Location Scanning (HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations)
* 

## MITRE Techniques Evaluated

Please be aware that some of these are (of course) more detected than others - for example, we are not detecting all possible registry modifications but rather inspecting certain keys for obvious changes and using that technique where no other technique is applicable.  For other items such as COM hijacking, we are inspecting all entries in the relevant registry key and bubbling them all up to the surface, having a much more complete detection surface.

* T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)
* T1037.005: Boot or Logon Initialization Scripts: Startup Items
* T1059: Command and Scripting Interpreter
* T1071: Application Layer Protocol
* T1098: Account Manipulation
* T1112: Modify Registry
* T1053: Scheduled Task/Job
* T1136: Create Account
* T1137.001: Office Application Office Template Macros
* T1137.002: Office Application Startup: Office Test
* T1137.006: Office Application Startup: Add-ins
* T1197: BITS Jobs
* T1505.005: Server Software Component: Terminal Services DLL
* T1543.003: Create or Modify System Process: Windows Service
* T1546: Event Triggered Execution
* T1546.002: Event Triggered Execution: Screensaver
* T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription
* T1546.007: Event Triggered Execution: Netsh Helper DLL
* T1546.008: Event Triggered Execution: Accessibility Features
* T1546.009: Event Triggered Execution: AppCert DLLs
* T1546.010: Event Triggered Execution: AppInit DLLs
* T1546.011: Event Triggered Execution: Application Shimming
* T1546.012: Event Triggered Execution: Image File Execution Options Injection
* T1546.013: Event Triggered Execution: PowerShell Profile
* T1546.015: Event Triggered Execution: Component Object Model Hijacking
* T1547.002: Boot or Logon Autostart Execution: Authentication Packages
* T1547.003: Boot or Logon Autostart Execution: Time Providers
* T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL
* T1547.005: Boot or Logon Autostart Execution: Security Support Provider
* T1547.009: Boot or Logon Autostart Execution: Shortcut Modification
* T1547.012: Boot or Logon Autostart Execution: Print Processors
* T1547.014: Boot or Logon Autostart Execution: Active Setup
* T1553: Subvert Trust Controls
* T1556.002: Modify Authentication Process: Password Filter DLL
* T1574: Hijack Execution Flow
* T1574.007: Hijack Execution Flow: Path Interception by PATH Environment Variable
* T1574.009: Hijack Execution Flow: Path Interception by Unquoted Path
