<p align="center">
<img src="logo.png" height="300">
</p>
<h1 align="center">
Dredging Windows for Persistence 
</h1>

## What is Trawler?

Trawler is a PowerShell script designed to help Incident Responders discover potential indicators of compromise on Windows hosts, primarily focused on persistence mechanisms including Scheduled Tasks, Services, Registry Modifications, Startup Items, Binary Modifications and more.

## How do I use it?
Just download and run trawler.ps1 from an Administrative PowerShell/cmd prompt - any detections will be displayed in the console as well as written to a CSV ('detections.csv') in the current working directory.

Or use this one-liner from an Administrative PowerShell terminal:
```
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/joeavanzato/Trawler/main/trawler.ps1'))
```

## Example Image
<p align="center">
<img src="sample.PNG">
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
* Certain COM Object Hijacking
* LSA Notification Hijacking
* 'Office test' Usage
* Office GlobalDotName Usage
* Terminal Services DLL Hijacking

