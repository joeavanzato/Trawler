function Search-ScreenSaverEXE {
	# Supports Drive Retargeting
	Write-Message "Checking ScreenSaver exe"
	$basepath = "Registry::HKEY_CURRENT_USER\Control Panel\Desktop"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path)
		{
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq "SCRNSAVE.exe")
				{
					$detection = [PSCustomObject]@{
						Name = 'Potential Persistence via ScreenSaver Executable Hijack'
						Risk = 'High'
						Source = 'Registry'
						Technique = "T1546.002: Event Triggered Execution: Screensaver"
						Meta = "Key Location: HKCU\Control Panel\Desktop, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}