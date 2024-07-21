function Search-AppInitDLLs {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking AppInit DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppInitDLLs'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_appinitdlls $_.Name $_.Value
					if ($result -eq $true){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential AppInit DLL Persistence'
						Risk = 'Medium'
						Source = 'Registry'
						Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
						Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
	$path = "Registry::$regtarget_hklm`Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppInitDLLs'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_appinitdlls $_.Name $_.Value
					if ($result -eq $true){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential AppInit DLL Persistence'
						Risk = 'Medium'
						Source = 'Registry'
						Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
						Meta = "Key Location: HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}

}