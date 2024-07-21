function Search-GPOExtensions {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking GPO Extension DLLs"
	$homedrive = $env:HOMEDRIVE
	$gpo_dll_allowlist = @(
		"$homedrive\Windows\System32\TsUsbRedirectionGroupPolicyExtension.dll"
		"$homedrive\Windows\System32\cscobj.dll"
		"$homedrive\Windows\System32\dskquota.dll"
		"$homedrive\Windows\System32\gpprefcl.dll"
		"$homedrive\Windows\System32\gpscript.dll"
		"$homedrive\Windows\System32\iedkcs32.dll"
		"$homedrive\Windows\System32\polstore.dll"
		"$homedrive\Windows\System32\srchadmin.dll"
		"$homedrive\Windows\System32\tsworkspace.dll"
		"$homedrive\Windows\system32\domgmt.dll"
		"$homedrive\Windows\system32\gpprnext.dll"
		"AppManagementConfiguration.dll"
		"WorkFoldersGPExt.dll"
		"appmgmts.dll"
		"auditcse.dll"
		"dggpext.dll"
		"domgmt.dll"
		"dmenrollengine.dll"
		"dot3gpclnt.dll"
		"fdeploy.dll"
		"gptext.dll"
		"gpprefcl.dll"
		"gpscript.dll"
		"hvsigpext.dll"
		"pwlauncher.dll"
		"scecli.dll"
		"wlgpclnt.dll"
	)

	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions"
	if (Test-Path -Path "Registry::$path") {
		$items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = "Registry::"+$item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'DllName' -and $_.Value -notin $gpo_dll_allowlist) {
					Write-SnapshotMessage -Key $item.Name -Value $_.Value -Source 'GPOExtensions'

					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_gpoextensions $item.Name $_.Value
						if ($result){
							continue
						}
					}
					$detection = [PSCustomObject]@{
						Name = 'Review: Non-Standard GPO Extension DLL'
						Risk = 'Medium'
						Source = 'Windows GPO Extensions'
						Technique = "T1484.001: Domain Policy Modification: Group Policy Modification"
						Meta = "Key: "+$item.Name+", DLL: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}