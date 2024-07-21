function Search-NetSHDLLs {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking NetSH DLLs"
	$standard_netsh_dlls = @(
		"authfwcfg.dll",
		"dhcpcmonitor.dll",
		"dot3cfg.dll",
		"fwcfg.dll",
		"hnetmon.dll",
		"ifmon.dll",
		"napmontr.dll",
		"netiohlp.dll",
		"netprofm.dll",
		"nettrace.dll",
		"nshhttp.dll",
		"nshipsec.dll",
		"nshwfp.dll",
		"p2pnetsh.dll",
		"peerdistsh.dll",
		"rasmontr.dll",
		"rpcnsh.dll",
		"WcnNetsh.dll",
		"whhelper.dll",
		"wlancfg.dll",
		"wshelper.dll",
		"wwancfg.dll"
	)
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Netsh"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Value -notin $standard_netsh_dlls) {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'NetshDLLs'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_netshdlls $_.Name $_.Value
					if ($result -eq $true){
						$pass = $true
					}
				}
				if ($pass -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Potential Persistence via Netsh Helper DLL Hijack'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546.007: Event Triggered Execution: Netsh Helper DLL"
						Meta = "Key Location: HKLM\SOFTWARE\Microsoft\Netsh, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}