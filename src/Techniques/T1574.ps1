function Search-PeerDistExtensionDll {
	# Supports Drive Targeting
	Write-Message "Checking PeerDistExtension DLL"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension"
	$expected_value = "peerdist.dll"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "PeerdistDllName" -and $_.Value -ne $expected_value) {
				$detection = [PSCustomObject]@{
					Name = 'PeerDist DLL does not match expected value'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Expected Value: $expected_value, Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-InternetSettingsLUIDll {
	# Supports Drive Retargeting
	Write-Message "Checking InternetSettings DLL"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\LUI"
	$expected_value = "$env_assumedhomedrive\Windows\system32\wininetlui.dll!InternetErrorDlgEx"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "0" -and $_.Value -ne $expected_value) {
				$detection = [PSCustomObject]@{
					Name = 'InternetSettings LUI Error DLL does not match expected value'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Expected Value: $expected_value, Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-ErrorHandlerCMD {
	# Support Drive Retargeting
	Write-Message "Checking ErrorHandler.cmd"
	$path = "$env_homedrive\windows\Setup\Scripts\ErrorHandler.cmd"
	if (Test-Path $path){

		$script_content_detection = $false
		try {
			$script_content = Get-Content $path
			foreach ($line_ in $script_content){
				if (Test-TrawlerSuspiciousTerms $line_ -and $script_content_detection -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Suspicious Content in ErrorHandler.cmd'
						Risk = 'High'
						Source = 'Windows'
						Technique = "T1574: Hijack Execution Flow"
						Meta = "File: $path, Suspicious Line: +$line_"
					}
					Write-Detection $detection
					$script_content_detection = $true
				}
			}
		} catch {
		}
		if ($script_content_detection -eq $false){
			$detection = [PSCustomObject]@{
				Name = 'Review: ErrorHandler.cmd Existence'
				Risk = 'High'
				Source = 'Windows'
				Technique = "T1574: Hijack Execution Flow"
				Meta = "File Location: $path"
			}
			Write-Detection $detection
		}
	}
}

function Search-BIDDll {
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	Write-Message "Checking BID DLL"
	$paths = @(
		"Registry::$regtarget_hklm`Software\Microsoft\BidInterface\Loader"
		"Registry::$regtarget_hklm`software\Wow6432Node\Microsoft\BidInterface\Loader"

	)
	$expected_values = @(
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework\\.*\\ADONETDiag\.dll"
		"$env:homedrive\\Windows\\SYSTEM32\\msdaDiag\.dll"

	)
	foreach ($path in $paths){
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq ":Path") {
					Write-SnapshotMessage -Key $path -Value $_.Value -Source 'BIDDLL'

					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_biddll $path $_.Value
						if ($result){
							continue
						}
					}
					$match = $false
					foreach ($val in $expected_values){
						if ($_.Value -match $val){
							$match = $true
							break
						}
					}
					if ($match -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Non-Standard Built-In Diagnostics (BID) DLL'
							Risk = 'High'
							Source = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-WindowsUpdateTestDlls {
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	Write-Message "Checking Windows Update Test"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Test"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -in "EventerHookDll","AllowTestEngine","AlternateServiceStackDLLPath") {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'WinUpdateTestDLL'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_winupdatetest $path $_.Value
					if ($result){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Windows Update Test DLL Exists'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-KnownManagedDebuggers {
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	Write-Message "Checking Known Managed Debuggers"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\KnownManagedDebuggingDlls"
	$allow_list = @(
		"$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
		"$env:homedrive\\Windows\\System32\\mrt_map\.dll"
	)
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $path -Value $_.Name -Source 'KnownManagedDebuggers'

			$pass = $false
			if ($loadsnapshot){
				$result = Confirm-IfAllowed $allowlist_knowndebuggers $path $_.Name
				if ($result){
					$pass = $true
				}
			}
			$matches_good = $false
			foreach ($allowed_item in $allow_list){
				if ($_.Name -match $allowed_item){
					$matches_good = $true
					break
				}
			}
			if ($matches_good -eq $false -and $pass -and $false){
				$detection = [PSCustomObject]@{
					Name = 'Non-Standard KnownManagedDebugging DLL'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "Key Location: $path, DLL: "+$_.Name
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-MiniDumpAuxiliaryDLLs {
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	Write-Message "Checking MiniDumpAuxiliary DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
	$allow_list = @(
		"$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\coreclr\.dll"
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\(mscorwks|clr)\.dll"
		"$env:homedrive\\Windows\\System32\\(chakra|jscript.*|mrt.*)\.dll"

	)
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $path -Value $_.Name -Source 'MiniDumpAuxiliaryDLL'

			$pass = $false
			if ($loadsnapshot){
				$result = Confirm-IfAllowed $allowlist_minidumpauxdlls $path $_.Name
				if ($result){
					$pass = $true
				}
			}
			$matches_good = $false
			foreach ($allowed_item in $allow_list){
				if ($_.Name -match $allowed_item){
					$matches_good = $true
					break
				}
			}
			if ($matches_good -eq $false -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Non-Standard MiniDumpAuxiliary DLL'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "Key Location: $path, DLL: "+$_.Name
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-Wow64LayerAbuse {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking WOW64 Compatibility DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Wow64\x86"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne "(Default)"){
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WOW64Compat'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_WOW64Compat $_.Name $_.Value
					if ($result){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Non-Standard Wow64\x86 DLL loaded into x86 process'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta = "Key Location: $path, Target Process Name: "+$_.Name+" Loaded DLL: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-EventViewerMSC {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Event Viewer MSC"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer"
		"Registry::$regtarget_hklm`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Event Viewer"
	)
	foreach ($path in $paths){
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -in "MicrosoftRedirectionProgram","MicrosoftRedirectionProgramCommandLineParameters","MicrosoftRedirectionURL" -and $_.Value -notin "","http://go.microsoft.com/fwlink/events.asp"){
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'MSCHijack'

					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_MSCHijack $_.Name $_.Value
						if ($result){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Event Viewer MSC Hijack'
							Risk = 'High'
							Source = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "Key Location: $path, Entry Name: "+$_.Name+" Loaded Value: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-SEMgrWallet {
	# TODO - Implement snapshot skipping
	# Supports Drive Retargeting
	Write-Message "Checking SEMgr Wallet DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\SEMgr\Wallet"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "DllName" -and $_.Value -notin "","SEMgrSvc.dll"){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'SEMgr'

				$detection = [PSCustomObject]@{
					Name = 'Potential SEMgr Wallet DLL Hijack'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "Key Location: $path, Entry: "+$_.Name+" Loaded DLL: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-WERRuntimeExceptionHandlers {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Error Reporting Handler DLLs"
	$allowed_entries = @(
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft\\Edge\\Application\\.*\\msedge_wer\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Common Files\\Microsoft Shared\\ClickToRun\\c2r64werhandler\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Google\\Chrome\\Application\\.*\\chrome_wer\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE.*\\msowercrash\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Visual Studio\\.*\\Community\\common7\\ide\\VsWerHandler\.dll"
		"$env_assumedhomedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
		"$env_assumedhomedrive\\Windows\\System32\\iertutil.dll"
		"$env_assumedhomedrive\\Windows\\System32\\msiwer.dll"
		"$env_assumedhomedrive\\Windows\\System32\\wbiosrvc.dll"
		"$env_assumedhomedrive\\(Program Files|Program Files\(x86\))\\Mozilla Firefox\\mozwer.dll"
	)
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {

			$verified_match = $false
			foreach ($entry in $allowed_entries){
				#Write-Host $entry
				if ($_.Name -match $entry -and $verified_match -eq $false){
					$verified_match = $true
				} else {
				}
			}

			if ($_.Name -ne "(Default)" -and $verified_match -eq $false){
				Write-SnapshotMessage -Key $path -Value $_.Name -Source 'WERHandlers'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_werhandlers $path $_.Name
					if ($result){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential WER Helper Hijack'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta = "Key Location: $path, DLL: "+$_.Name
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-ExplorerHelperUtilities {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Explorer Helper exes"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath"
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath"
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath"
	)
	$allowlisted_explorer_util_paths = @(
		"$env:SYSTEMROOT\system32\sdclt.exe"
		"$env:SYSTEMROOT\system32\cleanmgr.exe /D %c"
		"$env:SYSTEMROOT\system32\dfrgui.exe"
		"$env:SYSTEMROOT\system32\wbadmin.msc"
	)
	foreach ($path in $paths){
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -ne '""' -and $_.Value -notin $allowlisted_explorer_util_paths) {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'ExplorerHelpers'

					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_explorerhelpers $_.Value $_.Value
						if ($result -eq $true){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Explorer\MyComputer Utility Hijack'
							Risk = 'Medium'
							Source = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "Key Location: $path, Entry Name: "+$_.Name+", DLL: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-TerminalServicesInitialProgram {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Terminal Services Initial Programs"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
		"Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\WinStations\RDP-Tcp"
	)
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	foreach ($p in $regtarget_hkcu_list) {
		$paths += $basepath.Replace("HKEY_CURRENT_USER", $p)
	}

	foreach ($path in $paths){
		if (Test-Path -Path $path) {
			$finherit = $false
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'fInheritInitialProgram' -and $_.Value -eq "1"){
					$finherit = $true
				}
			}
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'InitialProgram' -and $_.Value -ne "" -and $finherit -eq $true){
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'TerminalServicesIP'

					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_termsrvinitialprogram $_.Value $_.Value
						if ($result -eq $true){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'TerminalServices InitialProgram Active'
							Risk = 'Medium'
							Source = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "Key Location: $path, Entry Name: "+$_.Name+", DLL: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-RDPStartupPrograms {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking RDP Startup Programs"
	$allowed_rdp_startups = @(
		"rdpclip"
	)
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\Wds\rdpwd"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'StartupPrograms' -and $_.Value -ne ""){
				$packages = $_.Value.Split(",")
				foreach ($package in $packages){
					if ($package -notin $allowed_rdp_startups){
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'RDPStartup'

						$pass = $false
						if ($loadsnapshot){
							$result = Confirm-IfAllowed $allowlist_rdpstartup $package $package
							if ($result -eq $true){
								$pass = $true
							}
						}
						if ($pass -eq $false){
							$detection = [PSCustomObject]@{
								Name = 'Non-Standard RDP Startup Program'
								Risk = 'Medium'
								Source = 'Registry'
								Technique = "T1574: Hijack Execution Flow"
								Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value+", Abnormal Package: "+$package
							}
							Write-Detection $detection
						}
					}
				}
			}
		}
	}
}

function Search-MSDTCDll {
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	Write-Message "Checking MSDTC DLL Hijack"
	$matches = @{
		"OracleOciLib" = "oci.dll"
		"OracleOciLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleSqlLib" = "SQLLib80.dll"
		"OracleSqlLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleXaLib" = "xa80.dll"
		"OracleXaLibPath" = "$env_assumedhomedrive\Windows\system32"
	}
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\MSDTC\MTxOCI"
	if (Test-Path -Path "Registry::$path") {
		$data = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$data.PSObject.Properties | ForEach-Object {
			if ($matches.ContainsKey($_.Name)){
				if ($_.Value -ne $matches[$_.Name]){
					$detection = [PSCustomObject]@{
						Name = 'MSDTC Key/Value Mismatch'
						Risk = 'Medium'
						Source = 'Windows MSDTC'
						Technique = "T1574: Hijack Execution Flow"
						Meta = "Key: "+$path+", Entry Name: "+$_.Name+", Entry Value: "+$_.Value+", Expected Value: "+$matches[$_.Name]
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-ProcessModules {
	# Supports Dynamic Snapshotting
	# Does not support Drive Retargeting
	if ($drivechange){
		Write-Message "Skipping Phantom DLLs - No Drive Retargeting"
		return
	}
	Write-Message "Checking 'Phantom' DLLs"
	$processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName,CreationDate,CommandLine,ExecutablePath,ParentProcessId,ProcessId
	$suspicious_unsigned_dll_names = @(
		"cdpsgshims.dll",
		"diagtrack_win.dll",
		"EdgeGdi.dll",
		"Msfte.dll",
		"phoneinfo.dll",
		"rpcss.dll",
		"sapi_onecore.dll",
		"spreview.exewdscore.dll",
		"Tsmsisrv.dll",
		"TSVIPSrv.dll",
		"Ualapi.dll",
		"UsoSelfhost.dll",
		"wbemcomn.dll",
		"WindowsCoreDeviceInfo.dll",
		"windowsperformancerecordercontrol.dll",
		"wlanhlp.dll",
		"wlbsctrl.dll",
		"wow64log.dll",
		"WptsExtensions.dll"
		"fveapi.dll"
	)
	foreach ($process in $processes){
		$modules = Get-Process -id $process.ProcessId -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty modules -ErrorAction SilentlyContinue | Select-Object Company,FileName,ModuleName
		if ($modules -ne $null){
			foreach ($module in $modules){
				if ($module.ModuleName -in $suspicious_unsigned_dll_names) {
					Write-SnapshotMessage -Key $module.FileName -Value $module.FileName -Source 'Modules'

					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_modules $module.FileName $module.FileName
						if ($result){
							continue
						}
					}
					$signature = Get-AuthenticodeSignature $module.FileName
					if ($signature.Status -ne 'Valid'){
						$item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
						$detection = [PSCustomObject]@{
							Name = 'Suspicious Unsigned DLL with commonly-masqueraded name loaded into running process.'
							Risk = 'Very High'
							Source = 'Processes'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "DLL: "+$module.FileName+", Process Name: "+$process.ProcessName+", PID: "+$process.ProcessId+", Execuable Path: "+$process.ExecutablePath+", DLL Creation Time: "+$item.CreationTime+", DLL Last Write Time: "+$item.LastWriteTime
						}
						Write-Detection $detection
					} else {
						$item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
						$detection = [PSCustomObject]@{
							Name = 'Suspicious DLL with commonly-masqueraded name loaded into running process.'
							Risk = 'High'
							Source = 'Processes'
							Technique = "T1574: Hijack Execution Flow"
							Meta = "DLL: "+$module.FileName+", Process Name: "+$process.ProcessName+", PID: "+$process.ProcessId+", Execuable Path: "+$process.ExecutablePath+", DLL Creation Time: "+$item.CreationTime+", DLL Last Write Time: "+$item.LastWriteTime
						}
						# TODO - This is too noisy to use as-is - these DLLs get loaded into quite a few processes.
						# Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-WindowsUnsignedFiles {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting - Not actually sure if this will work though
	Write-Message "Checking Unsigned Files"
	$scan_paths = @(
	"$env_homedrive\Windows",
	"$env_homedrive\Windows\System32",
	"$env_homedrive\Windows\System"
	"$env_homedrive\Windows\temp"
	)
	#allowlist_unsignedfiles
	foreach ($path in $scan_paths)
	{
		$files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".dll", ".exe" } | Select-Object *
		foreach ($file in $files)
		{
			$sig = Get-AuthenticodeSignature $file.FullName
			if ($sig.Status -ne 'Valid')
			{
				$item = Get-ChildItem -Path $file.FullName -File -ErrorAction SilentlyContinue | Select-Object *
				Write-SnapshotMessage -Key $file.FullName -Value $file.FullName -Source 'UnsignedWindows'

				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_unsignedfiles $file.FullName $file.FullName
					if ($result){
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name = 'Unsigned DLL/EXE present in critical OS directory'
					Risk = 'Very High'
					Source = 'Windows'
					Technique = "T1574: Hijack Execution Flow"
					Meta = "File: " + $file.FullName + ", Creation Time: " + $item.CreationTime + ", Last Write Time: " + $item.LastWriteTime
				}
				#Write-Host $detection.Meta
				Write-Detection $detection
			}
		}
	}
}

function Search-PATHHijacks {
	# Supports Dynamic Snapshotting
	# Mostly supports drive retargeting - assumed PATH is prefixed with C:
	# Data Stored at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment
	# Can just collect from this key instead of actual PATH var
	Write-Message "Checking PATH Hijacks"
	$system32_path = "$env_homedrive\windows\system32"
	$system32_bins = Get-ChildItem -File -Path $system32_path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object Name
	$sys32_bins = New-Object -TypeName "System.Collections.ArrayList"

	foreach ($bin in $system32_bins){
		$sys32_bins.Add($bin.Name) | Out-Null
	}
	$path_reg = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Session Manager\Environment"
	if (Test-Path -Path $path_reg) {
		$items = Get-ItemProperty -Path $path_reg | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "Path") {
				$path_entries = $_.Value
			}
		}
	}
	$path_entries = $path_entries.Split(";")
	$paths_before_sys32 = New-Object -TypeName "System.Collections.ArrayList"
	foreach ($path in $path_entries){
		$path = $path.Replace("C:", $env_homedrive)
		if ($path -ne $system32_path){
			$paths_before_sys32.Add($path) | Out-Null
		} else {
			break
		}
	}

	foreach ($path in $paths_before_sys32){
		$path_bins = Get-ChildItem -File -Path $path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object *
		foreach ($bin in $path_bins){
			if ($bin.Name -in $sys32_bins){
				Write-SnapshotMessage -Key $bin.FullName -Value $bin.Name -Source 'PATHHijack'

				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_pathhijack $bin.FullName
					if ($result){
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name = 'Possible PATH Binary Hijack - same name as SYS32 binary in earlier PATH entry'
					Risk = 'Very High'
					Source = 'PATH'
					Technique = "T1574.007: Hijack Execution Flow: Path Interception by PATH Environment Variable"
					Meta = "File: " + $bin.FullName + ", Creation Time: " + $bin.CreationTime + ", Last Write Time: " + $bin.LastWriteTime
				}
				#Write-Host $detection.Meta
				Write-Detection $detection
			}
		}

	}
}

function Search-ServiceHijacks {
	Write-Message "Checking Un-Quoted Services"
	# Supports Drive Retargeting, assumes homedrive is C:
	#$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
	$service_path = "$regtarget_hklm`SYSTEM\$currentcontrolset\Services"
	$service_list = New-Object -TypeName "System.Collections.ArrayList"
	if (Test-Path -Path "Registry::$service_path") {
		$items = Get-ChildItem -Path "Registry::$service_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSProvider
			if ($data.ImagePath -ne $null){
				$service = [PSCustomObject]@{
					Name = $data.PSChildName
					PathName = $data.ImagePath
				}
				$service.PathName = $service.PathName.Replace("\SystemRoot", "$env_assumedhomedrive\Windows")
				$service_list.Add($service) | Out-Null
			}
		}
	}
	foreach ($service in $service_list){
		$service.PathName = ($service.PathName).Replace("C:", $env_homedrive)
		if ($service.PathName -match '".*"[\s]?.*') {
			# Skip Paths where the executable is contained in quotes
			continue
		}
		# Is there a space in the service path?
		if ($service.PathName.Contains(" ")) {
			$original_service_path = $service.PathName
			# Does the path contain a space before the exe?
			if ($original_service_path -match '.*\s.*\.exe.*'){
				$tmp_path = $original_service_path.Split(" ")
				$base_path = ""
				foreach ($path in $tmp_path){
					$base_path += $path
					$test_path = $base_path + ".exe"
					if (Test-Path $test_path) {
						$detection = [PSCustomObject]@{
							Name = 'Possible Service Path Hijack via Unquoted Path'
							Risk = 'High'
							Source = 'Services'
							Technique = "T1574.009: Create or Modify System Process: Windows Service"
							Meta = "Service Name: "+ $service.Name+", Service Path: "+ $service.PathName+", Suspicious File: "+$test_path
						}
						Write-Detection $detection
					}
					$base_path += " "
				}
			}
		}
	}
}