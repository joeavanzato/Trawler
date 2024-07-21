function Search-ApplicationShims {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Application Shims"
	# TODO - Also check HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppShims'

			$pass = $false
			if ($loadsnapshot){
				$result = Confirm-IfAllowed $allowlist_appshims $_.Value $_.Value
				if ($result -eq $true){
					$pass = $true
				}
			}
			if ($pass -eq $false){
				$detection = [PSCustomObject]@{
					Name = 'Potential Application Shimming Persistence'
					Risk = 'High'
					Source = 'Registry'
					Technique = "T1546.011: Event Triggered Execution: Application Shimming"
					Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}