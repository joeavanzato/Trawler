# Snapshot acts as a custom allow-list for a specific gold-image or enterprise environment
# Run trawler once like '.\trawler.ps1 -snapshot' to generate 'snapshot.csv
# $message.key = Lookup component for allow-list hashtable
# $message.value = Lookup component for allow-list hashtable
# $message.source = Where are the K/V sourced from
# TODO - Consider implementing this as JSON instead of CSV for more detailed storage and to easier support in-line modification by other tools
function Write-SnapshotMessage() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[string]
		$Key,
		[Parameter()]
		[string]
		$Value,
		[Parameter(Mandatory=$true)]
		[string]
		$Source
	)

	# Only write when writable and snapshot is specified
	if (-not ($script:snapshotpath_writable -and $snapshot)) {
		return;
	}

	[PSCustomObject]@{
		Key = $Key
		Value = $Value
		Source = $Source
	} | Export-CSV $snapshotpath -Append -NoTypeInformation -Encoding UTF8
}

function Read-Snapshot(){
	Write-Host "[+] Reading Snapshot File: $loadsnapshot"
	if (-not(Test-Path $loadsnapshot)){
		Write-Host "[!] Specified snapshot file does not exist!" -ForegroundColor "Yellow"
		exit
	}

	$csv_data = Import-CSV $loadsnapshot
	$script:AllowData = $csv_data
	
	$script:allowtable_scheduledtask = @{}
	$script:allowlist_users = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_services = @{}
	$script:allowlist_process_exes = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_remote_addresses = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_wmi_consumers = @{}
	$script:allowlist_startup_commands = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_bits = @{}
	$script:allowtable_debuggers = @{}
	$script:allowlist_debuggers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_outlookstartup = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_com = @{}
	$script:allowtable_services_reg = @{}
	$script:allowlist_modules = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_unsignedfiles = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_pathhijack = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_fileassocations = @{}
	$script:allowtable_certificates = @{}
	$script:allowlist_officeaddins = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_gposcripts = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_knowndebuggers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_uninstallstrings = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_werhandlers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_printmonitors = @{}
	$script:allowtable_printprocessors = @{}
	$script:allowlist_nlpdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_apppaths = @{}
	$script:allowlist_gpoextensions = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_biddll = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_winupdatetest = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_minidumpauxdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_WOW64Compat = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_MSCHijack = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_telemetry = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_activesetup = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_uninstallstrings = @{}
	$script:allowtable_quietuninstallstrings = @{}
	$script:allowlist_policymanagerdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_listeningprocs = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_silentprocessexit = @{}
	$script:allowlist_winlogonhelpers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_rdpshadow = @{}
	$script:allowtable_remoteuac = @{}
	$script:allowlist_lsasecurity = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_dnsplugin = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_explorerhelpers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_termsrvinitialprogram = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_rdpstartup = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_timeproviders = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_userinitmpr = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_netshdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_appcertdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_appinitdlls = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_appshims = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowtable_ifeodebuggers = @{}
	$script:allowlist_folderopen = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_globaldotname = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_cmdautorunproc = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_rats = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_office_trusted_locations = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_contextmenuhandlers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_bootverificationprogram = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_diskcleanuphandlers = New-Object -TypeName "System.Collections.ArrayList"
	$script:allowlist_disablelowil = New-Object -TypeName "System.Collections.ArrayList"
	
	foreach ($item in $csv_data) {
		switch ($item.Source) {
			"Scheduled Tasks" {
				# Using scheduled task name and exe path
				# TODO - Incorporate Task Arguments
				$allowtable_scheduledtask[$item.Key] = $item.Value
			}
			"Users" {
				$allowlist_users.Add($item.Key) | Out-Null
			}
			"ContextMenuHandlers" {
				$allowlist_contextmenuhandlers.Add($item.Value) | Out-Null
			}
			"DisableLowIL" {
				$allowlist_disablelowil.Add($item.Value) | Out-Null
			}
			"DiskCleanupHandlers" {
				$allowlist_diskcleanuphandlers.Add($item.Value) | Out-Null
			}
			"BootVerificationProgram" {
				$allowlist_bootverificationprogram.Add($item.Value) | Out-Null
			}
			"IFEO" {
				$allowtable_ifeodebuggers[$item.Key] = $item.Value
			}
			"AppShims" {
				$allowlist_appshims.Add($item.Value) | Out-Null
			} 
			"OfficeTrustedLocations" {
				$allowlist_office_trusted_locations.Add($item.Value) | Out-Null
			} 
			"RATS" {
				$allowlist_rats.Add($item.Key) | Out-Null
			} 
			"CommandAutorunProcessor" {
				$allowlist_cmdautorunproc.Add($item.Value) | Out-Null
			} 
			"GlobalDotName" {
				$allowlist_globaldotname.Add($item.Value) | Out-Null
			} 
			"FolderOpen" {
				$allowlist_folderopen.Add($item.Value) | Out-Null
			} 
			"UserInitMPR" {
				$allowlist_userinitmpr.Add($item.Value) | Out-Null
			} 
			"NetshDLLs" {
				$allowlist_netshdlls.Add($item.Value) | Out-Null
			} 
			"AppCertDLLs" {
				$allowlist_appcertdlls.Add($item.Value) | Out-Null
			} 
			"AppInitDLLs" {
				$allowlist_appinitdlls.Add($item.Value) | Out-Null
			} 
			"LSASecurity" {
				$allowlist_lsasecurity.Add($item.Value) | Out-Null
			} 
			"TimeProviders" {
				$allowlist_timeproviders.Add($item.Value) | Out-Null
			} 
			"ExplorerHelpers" {
				$allowlist_explorerhelpers.Add($item.Value) | Out-Null
			} 
			"RDPStartup" {
				$allowlist_rdpstartup.Add($item.Value) | Out-Null
			} 
			"DNSPlugin" {
				$allowlist_dnsplugin.Add($item.Value) | Out-Null
			} 
			"TerminalServicesIP" {
				$allowlist_termsrvinitialprogram.Add($item.Value) | Out-Null
			} 
			"RDPShadow" {
				$allowtable_rdpshadow[$item.Key] = $item.Value
			} 
			"RemoteUAC" {
				$allowtable_remoteuac[$item.Key] = $item.Value
			} 
			"BIDDLL" {
				$allowlist_biddll.Add($item.Value) | Out-Null
			} 
			"WinlogonHelpers" {
				$allowlist_winlogonhelpers.Add($item.Value) | Out-Null
			} 
			"ProcessConnections" {
				$allowlist_listeningprocs.Add($item.Value) | Out-Null
			}
			"PolicyManagerPreCheck" {
				$allowlist_policymanagerdlls.Add($item.Value) | Out-Null
			}
			"PolicyManagerTransport" {
				$allowlist_policymanagerdlls.Add($item.Value) | Out-Null
			} 
			"WinUpdateTestDLL" {
				$allowlist_winupdatetest.Add($item.Value) | Out-Null
			} 
			"ActiveSetup" {
				$allowlist_activesetup.Add($item.Value) | Out-Null
			} 
			"MiniDumpAuxiliaryDLL" {
				$allowlist_minidumpauxdlls.Add($item.Value) | Out-Null
			} 
			"WOW64Compat" {
				$allowlist_WOW64Compat.Add($item.Value) | Out-Null
			} 
			"MSCHijack" {
				$allowlist_MSCHijack.Add($item.Value) | Out-Null
			} 
			"TelemetryCommands" {
				$allowlist_telemetry.Add($item.Value) | Out-Null
			} 
			"UninstallString" {
				$allowtable_uninstallstrings[$item.Key] = $item.Value
			} 
			"QuietUninstallString" {
				$allowtable_quietuninstallstrings[$item.Key] = $item.Value
			} 
			"SilentProcessExit" {
				$allowtable_silentprocessexit[$item.Key] = $item.Value
			} 
			"Services" {
				# Using Service Name and Full Path
				$allowtable_services[$item.Key] = $item.Value
			} 
			"Processes" {
				# Using Process Executable Path
				$allowlist_process_exes.Add($item.Value) | Out-Null
			} 
			"Connections" {
				# Using Remote Address
				$allowlist_remote_addresses.Add($item.Value) | Out-Null
			} 
			"WMI Consumers" {
				# Using Name and CommandLineTemplate/ScriptFilePath
				$allowtable_wmi_consumers[$item.Key] = $item.Value
			} 
			"Startup" {
				# Using execution 'command'
				$allowlist_startup_commands.Add($item.Value) | Out-Null
			} 
			"BITS" {
				# Using Name and 'Command'
				$allowtable_bits[$item.Key] = $item.Value
			} 
			"Debuggers" {
				# Using Name and Debugger File Path
				$allowtable_debuggers[$item.Key] = $item.Value
				$allowlist_debuggers.Add($item.Value) | Out-Null
			} 
			"Outlook" {
				# Using DLL Name as value
				$allowlist_outlookstartup.Add($item.Value) | Out-Null
			} 
			"COM" {
				# Using reg path and associated file
				$allowtable_com[$item.Key] = $item.Value
			} 
			"Services_REG" {
				# Using reg path and value
				$allowtable_services_reg[$item.Key] = $item.Value
			} 
			"Modules" {
				# Using DLL Name as value
				$allowlist_modules.Add($item.Value) | Out-Null
			} 
			"UnsignedWindows" {
				# Using file fullpath
				$allowlist_unsignedfiles.Add($item.Value) | Out-Null
			} 
			"PATHHijack" {
				# Using file fullpath
				$allowlist_pathhijack.Add($item.Key) | Out-Null
			} 
			"AssociationHijack" {
				# Using file shortname and associated command
				$allowtable_fileassocations[$item.Key] = $item.Value
			} 
			"Certificates" {
				# Using Issuer and Subject
				$allowtable_certificates[$item.Key] = $item.Value
			} 
			"OfficeAddins" {
				# Using full path
				$allowlist_officeaddins.Add($item.Value) | Out-Null
			} 
			"GPOScripts" {
				# Using full path
				$allowlist_gposcripts.Add($item.Value) | Out-Null
			} 
			"KnownManagedDebuggers" {
				# Using full path
				$allowlist_knowndebuggers.Add($item.Value) | Out-Null
			} 
			"UninstallString" {
				# Using command
				$allowlist_uninstallstrings.Add($item.Value) | Out-Null
			} 
			"WERHandlers" {
				# Using filepath
				$allowlist_werhandlers.Add($item.Value) | Out-Null
			} 
			"PrintMonitors" {
				# Using key name and DLL path
				$allowtable_printmonitors[$item.Key] = $item.Value
			} 
			"PrintProcessors" {
				# Using key name and DLL path
				$allowtable_printprocessors[$item.Key] = $item.Value
			} 
			"NLPDlls" {
				# Using DLL path
				$allowlist_nlpdlls.Add($item.Value) | Out-Null
			} 
			"AppPaths" {
				# Using Reg Key and associated value
				$allowtable_apppaths[$item.Key] = $item.Value
			} 
			"GPOExtensions" {
				# Using Reg Key and associated value
				$allowlist_gpoextensions.Add($item.Value) | Out-Null
			}
			
			Default {
				Write-Warning "Unknown snapshot source found $($item.Source)"
			}
		}
	}
}

function Confirm-IfAllowed($allowmap, $key, $val, $det){
	if ($allowmap.GetType().Name -eq "Hashtable"){
		if ($allowmap.ContainsKey($key)){
			if ($allowmap[$key] -eq $val){
				return $true
			} elseif ($allowmap[$key] -eq "" -and [string]::IsNullOrWhiteSpace($val)) {
				return $true
			} else {
				Write-Detection $det
				return $false
			}
		}
	} elseif ($allowmap.GetType().Name -eq "ArrayList"){
		if ($allowmap.Contains($key) -or $allowmap.Contains($val)){
			return $true
		} else {
			return $false
		}
	} else {
		Write-Warning "Invalid AllowMap Type Specified"
	}
}

function Search-AllowList() {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Source,
		[Parameter()]
		[string]
		$Key,
		[Parameter()]
		[string]
		$Value
	)

	$checkList = $AllowData | Where-Object Source -eq $Source

	return $checkList.Key -contains $Key -or $checkList.Value -contains $Value
}

function Search-AllowHashTable() {
	[CmdletBinding()]
	param (
		[Parameter()]
		[Hashtable]
		$Source,
		[Parameter()]
		[string]
		$Key,
		[Parameter()]
		[string]
		$Value,
		[Parameter()]
		[object]
		$Detection
	)

	$checkList = ($AllowData | Where-Object Source -eq $Source) | Where-Object Key -eq $Key | Select-Object * -Unique

	if (!$checkList) {
		return $false
	}

	if ($checkList.Key -eq $Key -and $checkList.Value -eq $Value) {
		return $true 
	} else {
		Write-Detection $Detection
		return $false
	}
}