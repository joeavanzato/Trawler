<p align="center">
<img src="logo.png" height="300">
</p>
<h1 align="center">
Dredging Windows for Persistence 
</h1>

## What is Trawler?

Trawler is a PowerShell script designed to help Incident Responders discover potential indicators of compromise on Windows hosts, primarily focused on persistence mechanisms including Scheduled Tasks, Services, Registry Modifications, Startup Items, Binary Modifications and more.

Currently it can detect most of the persistence techniques specifically called out by MITRE and Atomic Red Team with more detections being added on a regular basis.
## How do I use it?
Just download and run trawler.ps1 from an Administrative PowerShell/cmd prompt - any detections will be displayed in the console as well as written to a CSV ('detections.csv') in the current working directory.

Or use this one-liner from an Administrative PowerShell terminal:
```
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/joeavanzato/Trawler/main/trawler.ps1'))
```

Certain detections have allow-lists built-in to help remove noise from default Windows configurations - expected Scheduled Tasks, Services, etc.  Of course, it is always possible for attackers to hijack these directly and masquerade with great detail as a default OS process - take care to use multiple forms of analysis and detection when dealing with skillful adversaries.

If you have examples, write-ups or ideas for additional detections, please feel free to submit an Issue or PR with relevant technical details/references - the code-base is a little messy right now and will be cleaned up over time.

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

TODO
* Browser Extension Analysis
* File Association Hijacking
* Certificate Installation (https://www.ired.team/offensive-security/persistence/t1130-install-root-certificate)
* Maybe: Temporary RID Hijacking (https://www.ired.team/offensive-security/persistence/rid-hijacking)
* Improve Office Trusted Location Scanning (HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations)
* 

