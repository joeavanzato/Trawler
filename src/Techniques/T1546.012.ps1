function Search-IFEO {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Image File Execution Options"
	$path = "Registry::$regtarget_hklm`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			if ($data.Debugger -ne $null){
				Write-SnapshotMessage -Key $item.Name -Value $data.Debugger -Source 'IFEO'

				if ($loadsnapshot){
					$detection = [PSCustomObject]@{
						Name = 'Allowlist Mismatch: IFEO Debugger'
						Risk = 'Medium'
						Source = 'Registry'
						Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
						Meta = "Registry Path: "+$item.Name+", Debugger: "+$data.Debugger
					}
					$result = Confirm-IfAllowed $allowtable_ifeodebuggers $item.Name $data.Debugger $detection
					if ($result -eq $true){
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name = 'Potential Image File Execution Option Debugger Injection'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
					Meta = "Registry Path: "+$item.Name+", Debugger: "+$data.Debugger
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-RegistryChecks {
	# DEPRECATED FUNCTION
	#TODO - Inspect File Command Extensions to hunt for anomalies
	# https://attack.mitre.org/techniques/T1546/001/

	# COM Object Hijack Scan
	# NULL this out for now since it should be covered in following COM functionality - this function is deprecated
	if (Test-Path -Path "Registry::HKCU\SOFTWARE\Classes\CLSIDNULL") {
		$items = Get-ChildItem -Path "Registry::HKCU\SOFTWARE\Classes\CLSID" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$children = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			foreach ($child in $children){
				$path = "Registry::"+$child.Name
				$data = Get-Item -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
				if ($data.Name -match '.*InprocServer32'){
					$datum = Get-ItemProperty $path
					$datum.PSObject.Properties | ForEach-Object {
						if ($_.Name -eq '(default)'){
							$detection = [PSCustomObject]@{
								Name = 'Potential COM Hijack'
								Risk = 'High'
								Source = 'Registry'
								Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
								Meta = "Registry Path: "+$data.Name+", DLL Path: "+$_.Value
							}
							#Write-Detection $detection
							# This is now handled by Search-COMHijacks along with HKLM and HKCR checks (which should be identical)
						}
					}
				}
			}
		}
	}
}

function Search-SilentProcessExitMonitoring {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking SilentProcessExit Monitoring"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			if ($data.MonitorProcess -ne $null){
				if ($data.ReportingMode -eq $null){
					$data.ReportingMode = 'NA'
				}

				Write-SnapshotMessage -Key $item.Name -Value $data.MonitorProcess -Source 'SilentProcessExit'

				if ($loadsnapshot){
					$detection = [PSCustomObject]@{
						Name = 'Allowlist Mismatch: Process Launched on SilentProcessExit'
						Risk = 'Medium'
						Source = 'Registry'
						Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
						Meta = "Monitored Process: "+$item.Name+", Launched Process: "+$data.MonitorProcess+", Reporting Mode: "+$data.ReportingMode
					}
					$result = Confirm-IfAllowed $allowtable_silentprocessexit $item.Name $data.MonitorProcess $detection
					if ($result){
						continue
					}
				}
				#allowtable_silentprocessexit
				$detection = [PSCustomObject]@{
					Name = 'Process Launched on SilentProcessExit'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
					Meta = "Monitored Process: "+$item.Name+", Launched Process: "+$data.MonitorProcess+", Reporting Mode: "+$data.ReportingMode
				}
				Write-Detection $detection
			}
		}
	}
}