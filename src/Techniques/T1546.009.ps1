function Search-AppCertDLLs {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking AppCert DLLs"
	$standard_appcert_dlls = @()
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Session Manager\AppCertDlls"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Value -notin $standard_appcert_dlls) {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppCertDLLs'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_appcertdlls $_.Name $_.Value
					if ($result -eq $true){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential Persistence via AppCertDLL Hijack'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546.009: Event Triggered Execution: AppCert DLLs"
						Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}