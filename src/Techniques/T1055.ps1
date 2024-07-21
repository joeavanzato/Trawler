function Search-DNSServerLevelPluginDLL {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking DNSServerLevelPlugin DLL"
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Services\DNS\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ServerLevelPluginDll' -and $_.Value -ne '""') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'DNSPlugin'

				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_dnsplugin $_.Value $_.Value
					if ($result -eq $true){
						return
					}
				}
				$detection = [PSCustomObject]@{
					Name = 'Review: DNS ServerLevelPluginDLL is active'
					Risk = 'Medium'
					Source = 'Registry'
					Technique = "T1055.001: Process Injection: Dynamic-link Library Injection"
					Meta = "Key Location: $path, Entry Name: "+$_.Name+", DLL: "+$_.Value
				}
				Write-Detection $detection
			}
		}
	}
}