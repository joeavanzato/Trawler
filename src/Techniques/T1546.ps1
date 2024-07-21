function Search-AppPaths {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking AppPaths"
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
	if (Test-Path -Path "Registry::$path") {
		$items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(default)') {
					$key_basename = [regex]::Matches($item.Name, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]
					$value_basename = [regex]::Matches($_.Value, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]
					if ($key_basename -ne $null -and $value_basename -ne $null){
						$value_basename = $value_basename.Replace('"', "")
						if ($key_basename -ne $value_basename){
							Write-SnapshotMessage -Key $item.Name -Value $_.Value -Source 'AppPaths'

							if ($loadsnapshot){
								$detection = [PSCustomObject]@{
									Name = 'Allowlist Mismatch: Potential App Path Hijacking - Executable Name does not match Registry Key'
									Risk = 'Medium'
									Source = 'Registry'
									Technique = "T1546: Event Triggered Execution"
									Meta = "Key Location: "+$item.Name+", Entry Name: "+$_.Name+", Entry Value: "+$_.Value
								}
								$result = Confirm-IfAllowed $allowtable_apppaths $item.Name $_.Value $detection
								if ($result){
									continue
								}
							}
							$detection = [PSCustomObject]@{
								Name = 'Potential App Path Hijacking - Executable Name does not match Registry Key'
								Risk = 'Medium'
								Source = 'Registry'
								Technique = "T1546: Event Triggered Execution"
								Meta = "Key Location: "+$item.Name+", Entry Name: "+$_.Name+", Entry Value: "+$_.Value
							}
							Write-Detection $detection
						}
					}
				}
			}
		}
	}
}

function Search-CommandAutoRunProcessors {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Command AutoRun Processors"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Command Processor"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AutoRun'){
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'CommandAutorunProcessor'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_cmdautorunproc $_.Value $_.Value
					if ($result -eq $true){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential Hijacking of Command AutoRun Processor'
						Risk = 'Very High'
						Source = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'AutoRun') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'CommandAutorunProcessor'

					$pass = $false
					if ($loadsnapshot)
					{
						$result = Confirm-IfAllowed $allowlist_cmdautorunproc $_.Value $_.Value
						if ($result -eq $true)
						{
							$pass = $true
						}
					}
					if ($pass -eq $false)
					{
						$detection = [PSCustomObject]@{
							Name = 'Potential Hijacking of Command AutoRun Processor'
							Risk = 'Very High'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Key Location: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-ContextMenu {
	# HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# HKEY_USERS\S-1-5-21-63485881-451500365-4075260605-1001\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# The general idea is that {B7CDF620-DB73-44C0-8611-832B261A0107} represents the Explorer context menu - we are scanning ALL ContextMenuHandlers for DLLs present in the (Default) property as opposed to a CLSID
	# https://ristbs.github.io/2023/02/15/hijack-explorer-context-menu-for-persistence-and-fun.html
	# Supports Drive Retargeting
	# No Snapshotting right now - can add though.
	# TODO - Check ColumnHandlers, CopyHookHandlers, DragDropHandlers and PropertySheetHandlers in same key, HKLM\Software\Classes\*\shellex
	Write-Message "Checking Context Menu Handlers"

	$path = "$regtarget_hklm`SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
					Write-SnapshotMessage -Key $item.Name -Value $_.Value -Source 'ContextMenuHandlers'

					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_contextmenuhandlers $_.Value $_.Value
						if ($result){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'DLL loaded in ContextMenuHandler'
							Risk = 'Medium'
							Source = 'Windows Context Menu'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Key: "+$item.Name+", DLL: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}

	$basepath = "HKEY_CURRENT_USER\SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -LiteralPath "Registry::$path") {
			$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			foreach ($item in $items) {
				$path = "Registry::"+$item.Name
				$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
				$data.PSObject.Properties | ForEach-Object {
					if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
						$detection = [PSCustomObject]@{
							Name = 'DLL loaded in ContextMenuHandler'
							Risk = 'Medium'
							Source = 'Windows Context Menu'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Key: "+$item.Name+", DLL: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-DiskCleanupHandlers {
	# Supports Retargeting/Snapshot
	Write-Message "Checking DiskCleanupHandlers"
	$default_cleanup_handlers = @(
		"C:\Windows\System32\DATACLEN.DLL",
		"C:\Windows\System32\PeerDistCleaner.dll",
		"C:\Windows\System32\D3DSCache.dll",
		"C:\Windows\system32\domgmt.dll",
		"C:\Windows\System32\pnpclean.dll",
		"C:\Windows\System32\occache.dll",
		"C:\Windows\System32\ieframe.dll",
		"C:\Windows\System32\LanguagePackDiskCleanup.dll",
		"C:\Windows\system32\setupcln.dll",
		"C:\Windows\system32\shell32.dll",
		"C:\Windows\system32\wmp.dll",
		"C:\Windows\System32\thumbcache.dll",
		"C:\Windows\system32\scavengeui.dll",
		"C:\Windows\System32\fhcleanup.dll"
	)
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)') {
					$target_prog = ''
					$tmp_path = "$regtarget_hkcr`CLSID\$($_.Value)\InProcServer32"
					if (Test-Path -LiteralPath "Registry::$tmp_path"){
						$data_tmp = Get-ItemProperty -LiteralPath "Registry::$tmp_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
						$data_tmp.PSObject.Properties | ForEach-Object {
							if ($_.Name -eq '(Default)'){
								$target_prog = $_.Value
							}
						}
					}
					if ($target_prog -in $default_cleanup_handlers){
						continue
					}
					Write-SnapshotMessage -Key $item.Name -Value $target_prog -Source 'DiskCleanupHandlers'
					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_diskcleanuphandlers $_.target_prog $_.target_prog
						if ($result){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Non-Default DiskCleanupHandler Program'
							Risk = 'Low'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Key: "+$item.Name+", Program: "+$target_prog
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-DebuggerHijacks {
	Write-Message "Checking Debuggers"
	# Partially Supports Dynamic Snapshotting
	# Support Drive Retargeting
	function Search-Debugger-Hijack-Allowlist ($key,$val){
		if ($loadsnapshot){
			$detection = [PSCustomObject]@{
				Name = 'Allowlist Mismatch: Debugger'
				Risk = 'Medium'
				Source = 'Registry'
				Technique = "T1546: Event Triggered Execution"
				Meta = "Key Location: $key, Entry Value: "+$val
			}
			$result = Confirm-IfAllowed $allowtable_debuggers $key $val $detection
			if ($result){
				return $true
			}
		}
		return $false
	}
	# TODO - Rearrange this code to use an array of paths and key names
	# allowtable_debuggers
	# Debugger Hijacks
	# AeDebug 32
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -in 'Debugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential AeDebug Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ProtectedDebugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value-Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential AeDebug Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}

	# AeDebug 64
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Debugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential AeDebug Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ProtectedDebugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential AeDebug Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}

	# .NET 32
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\.NETFramework"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'DbgManagedDebugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential .NET Debugger Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# .NET 64
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'DbgManagedDebugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d" -and $pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential .NET Debugger Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# Microsoft Script Debugger
	$path = "$regtarget_hklm`SOFTWARE\Classes\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq '@'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if ($_.Name -eq '@' -and $pass -eq $false -and ($_.Value -ne "`"$env:homedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env:homedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")){
				$detection = [PSCustomObject]@{
					Name = 'Potential Microsoft Script Debugger Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$basepath = "HKEY_CLASSES_ROOT\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
	foreach ($p in $regtarget_hkcu_class_list) {
		$path = $basepath.Replace("HKEY_CLASSES_ROOT", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '@'){
					Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

					if (Search-Debugger-Hijack-Allowlist $path $_.Value){
						$pass = $true
					}
				}
				if ($_.Name -eq '@' -and $pass -eq $false -and ($_.Value -ne "`"$env_assumedhomedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env_assumedhomedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")){
					$detection = [PSCustomObject]@{
						Name = 'Potential Microsoft Script Debugger Hijacking'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
	# Process Debugger
	$path = "$regtarget_hklm`SOFTWARE\Classes\CLSID\{78A51822-51F4-11D0-8F20-00805F2CD064}\InprocServer32"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq '(default)'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					$pass = $true
				}
			}
			if (($_.Name -in '(default)' -and $pass -eq $false -and $_.Value -ne "$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\VS7Debug\pdm.dll") -or ($_.Name -eq '@' -and $_.Value -ne "`"$env_assumedhomedrive\WINDOWS\system32\pdm.dll`"")){
				$detection = [PSCustomObject]@{
					Name = 'Potential Process Debugger Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# WER Debuggers
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs"
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Debugger'){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Search-Debugger-Hijack-Allowlist $path $_.Value){
					continue
				}
			}
			if ($_.Name -in 'Debugger','ReflectDebugger'){
				$detection = [PSCustomObject]@{
					Name = 'Potential WER Debugger Hijacking'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-DisableLowILProcessIsolation {
	# Supports Drive Retargeting
	# Supports Snapshotting
	Write-Message "Checking for COM Objects running without Low Integrity Isolation"
	$path = "$regtarget_hklm`Software\Classes\CLSID"
	$allowlist = @(
		"@C:\\Program Files\\Microsoft Office\\Root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\Office16\\oregres\.dll.*"
		"@wmploc\.dll.*"
		"@C:\\Windows\\system32\\mssvp\.dll.*"
		"@C:\\Program Files\\Common Files\\System\\wab32res\.dll.*"
	)
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'DisableLowILProcessIsolation' -and $_.Value -eq 1) {
					Write-SnapshotMessage -Key $item.Name -Value $item.Name -Source 'DisableLowIL'
					if ($data.DisplayName){
						$displayname =  $data.DisplayName
					} else {
						$displayname = ""
					}
					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_disablelowil $item.Name $item.Name
						if ($result){
							$pass = $true
						}
					}
					foreach ($allow in $allowlist){
						if ($displayname -match $allow){
							$pass = $true
							break
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'COM Object Registered with flag disabling low-integrity process isolation'
							Risk = 'Medium'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Key: "+$item.Name+", Display Name: "+$displayname
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-Narrator {
	# Supports Drive Retargeting
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	Write-Message "Checking Narrator MSTTSLocEnUS.dll Presence"
	$basepath = "$env_homedrive\Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL"
	if (Test-Path $basepath){
		$item = Get-Item -Path $basepath -ErrorAction SilentlyContinue | Select-Object *
		$detection = [PSCustomObject]@{
			Name = 'Narrator Missing DLL is Present'
			Risk = 'Medium'
			Source = 'Windows Narrator'
			Technique = "T1546: Event Triggered Execution"
			Meta = "File: "+$item.FullName+", Created: "+$item.CreationTime+", Last Modified: "+$item.LastWriteTime
		}
		Write-Detection $detection
	}
}

function Search-NotepadPlusPlusPlugins {
	# https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/
	# Supports Drive Retargeting
	Write-Message "Checking Notepad++ Plugins"
	$basepaths = @(
		"$env_homedrive\Program Files\Notepad++\plugins"
		"$env_homedrive\Program Files (x86)\Notepad++\plugins"
	)
	$allowlisted = @(
		".*\\Config\\nppPluginList\.dll"
		".*\\mimeTools\\mimeTools\.dll"
		".*\\NppConverter\\NppConverter\.dll"
		".*\\NppExport\\NppExport\.dll"
	)
	foreach ($basepath in $basepaths){
		if (Test-Path $basepath){
			$dlls = Get-ChildItem -Path $basepath -File -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
			#Write-Host $dlls
			foreach ($item in $dlls){
				$match = $false
				foreach ($allow_match in $allowlisted){
					if ($item.FullName -match $allow_match){
						$match = $true
					}
				}
				if ($match -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Non-Default Notepad++ Plugin DLL'
						Risk = 'Medium'
						Source = 'Notepad++'
						Technique = "T1546: Event Triggered Execution"
						Meta = "File: "+$item.FullName+", Created: "+$item.CreationTime+", Last Modified: "+$item.LastWriteTime
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-OfficeAI {
	# Supports Drive Retargeting
	# https://twitter.com/Laughing_Mantis/status/1645268114966470662
	Write-Message "Checking Office AI.exe Presence"
	$basepath = "$env_homedrive\Program Files\Microsoft Office\root\Office*"
	if (Test-Path $basepath){
		$path = "$env_homedrive\Program Files\Microsoft Office\root"
		$dirs = Get-ChildItem -Path $path -Directory -Filter "Office*" -ErrorAction SilentlyContinue
		foreach ($dir in $dirs){
			$ai = $dir.FullName+"\ai.exe"
			if (Test-Path $ai){
				$item = Get-Item -Path $ai -ErrorAction SilentlyContinue | Select-Object *
				$detection = [PSCustomObject]@{
					Name = 'AI.exe in Office Directory'
					Risk = 'Medium'
					Source = 'Windows Context Menu'
					Technique = "T1546: Event Triggered Execution"
					Meta = "File: "+$item.FullName+", Created: "+$item.CreationTime+", Last Modified: "+$item.LastWriteTime
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-UninstallStrings {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Uninstall Strings"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			#allowtable_uninstallstrings
			if ($data.UninstallString){
				if (Test-TrawlerSuspiciousTerms $data.UninstallString){
					Write-SnapshotMessage -Key $item.Name -Value $data.UninstallString -Source 'UninstallString'

					$pass = $false
					if ($loadsnapshot){
						$detection = [PSCustomObject]@{
							Name = 'Allowlist Mismatch: Uninstall String with Suspicious Keywords'
							Risk = 'Medium'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Application: "+$item.Name+", Uninstall String: "+$data.UninstallString
						}
						$result = Confirm-IfAllowed $allowtable_uninstallstrings $item.Name $data.UninstallString $detection
						if ($result){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Uninstall String with Suspicious Keywords'
							Risk = 'High'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Application: "+$item.Name+", Uninstall String: "+$data.UninstallString
						}
						Write-Detection $detection
					}
				}
			}
			if ($data.QuietUninstallString){
				if (Test-TrawlerSuspiciousTerms $data.QuietUninstallString){
					Write-SnapshotMessage -Key $item.Name -Value $data.QuietUninstallString -Source 'QuietUninstallString'

					$pass = $false
					if ($loadsnapshot){
						$detection = [PSCustomObject]@{
							Name = 'Allowlist Mismatch: Uninstall String with Suspicious Keywords'
							Risk = 'Medium'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Application: "+$item.Name+", Uninstall String: "+$data.QuietUninstallString
						}
						$result = Confirm-IfAllowed $allowtable_quietuninstallstrings $item.Name $data.QuietUninstallString $detection
						if ($result){
							$pass = $true
						}
					}
					if ($pass -eq $false){
						$detection = [PSCustomObject]@{
							Name = 'Uninstall String with Suspicious Keywords'
							Risk = 'High'
							Source = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta = "Application: "+$item.Name+", Uninstall String: "+$data.QuietUninstallString
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-PolicyManager {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking PolicyManager DLLs"
	$allow_listed_values = @(
		"%SYSTEMROOT%\system32\PolicyManagerPrecheck.dll"
		"%SYSTEMROOT%\system32\hascsp.dll"
	)
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\PolicyManager\default"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$items_ = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			foreach ($subkey in $items_){
				$subpath = "Registry::"+$subkey.Name
				$data = Get-ItemProperty -Path $subpath | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
				if ($data.PreCheckDLLPath -ne $null){
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_policymanagerdlls $subkey.Name $data.PreCheckDLLPath
						if ($result){
							continue
						}
					}
					if ($data.PreCheckDLLPath -notin $allow_listed_values){
						Write-SnapshotMessage -Key $subkey.Name -Value $data.PreCheckDLLPath -Source 'PolicyManagerPreCheck'

						$pass = $false
						if ($loadsnapshot){
							$result = Confirm-IfAllowed $allowlist_activesetup $item.Name $data.StubPath
							if ($result){
								$pass = $true
							}
						}
						if ($pass -eq $false){
							$detection = [PSCustomObject]@{
								Name = 'Non-Standard Policy Manager DLL'
								Risk = 'High'
								Source = 'Registry'
								Technique = "T1546: Event Triggered Execution"
								Meta = "Path: "+$subkey.Name+", Entry Name: PreCheckDLLPath, DLL: "+$data.PreCheckDLLPath
							}
							Write-Detection $detection
						}
					}
				}
				if ($data.transportDllPath -ne $null){
					$pass = $false
					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_policymanagerdlls $subkey.Name $data.transportDllPath
						if ($result){
							$pass = $true
						}
					}
					if ($data.transportDllPath -notin $allow_listed_values){
						Write-SnapshotMessage -Key $subkey.Name -Value $data.transportDllPath -Source 'PolicyManagerTransport'

						if ($pass -eq $false){
							$detection = [PSCustomObject]@{
								Name = 'Non-Standard Policy Manager DLL'
								Risk = 'High'
								Source = 'Registry'
								Technique = "T1546: Event Triggered Execution"
								Meta = "Path: "+$subkey.Name+", Entry Name: transportDllPath, DLL: "+$data.transportDllPath
							}
							Write-Detection $detection
						}
					}
				}
			}

		}
	}
}

function Search-WindowsLoadKey {
	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	Write-Message "Checking Windows Load"
	$basepath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -in 'Load'){
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WindowsLoad'

					$detection = [PSCustomObject]@{
						Name = 'Potential Windows Load Hijacking'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-AutoDialDLL {
	# Supports Drive Retargeting
	Write-Message "Checking Autodial DLL"
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AutodialDLL' -and $_.Value -ne 'C:\Windows\System32\rasadhlp.dll'){
				$detection = [PSCustomObject]@{
					Name = 'Potential Hijacking of Autodial DLL'
					Risk = 'Very High'
					Source = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-HTMLHelpDLL {
	# Supports Drive Retargeting
	Write-Message "Checking HTML Help (.chm) DLL"
	$basepath = "HKEY_CURRENT_USER\Software\Microsoft\HtmlHelp Author"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'location'){
					$detection = [PSCustomObject]@{
						Name = 'Potential CHM DLL Hijack'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

