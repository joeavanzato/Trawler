function Search-ModifiedWindowsAccessibilityFeature {
	# TODO - Consider allow-listing here
	# Supports Drive Retargeting
	Write-Message "Checking Accessibility Binaries"
	$files_to_check = @(
		"$env_homedrive\Program Files\Common Files\microsoft shared\ink\HID.dll"
		"$env_homedrive\Windows\System32\AtBroker.exe",
		"$env_homedrive\Windows\System32\DisplaySwitch.exe",
		"$env_homedrive\Windows\System32\Magnify.exe",
		"$env_homedrive\Windows\System32\Narrator.exe",
		"$env_homedrive\Windows\System32\osk.exe",
		"$env_homedrive\Windows\System32\sethc.exe",
		"$env_homedrive\Windows\System32\utilman.exe"
	)
	foreach ($file in $files_to_check){ 
		$fdata = Get-Item $file -ErrorAction SilentlyContinue | Select-Object CreationTime,LastWriteTime
		if ($fdata.CreationTime -ne $null) {
			if ($fdata.CreationTime.ToString() -ne $fdata.LastWriteTime.ToString()){
				$detection = [PSCustomObject]@{
					Name = 'Potential modification of Windows Accessibility Feature'
					Risk = 'High'
					Source = 'Windows'
					Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
					Meta = "File: "+$file+", Created: "+$fdata.CreationTime+", Modified: "+$fdata.LastWriteTime
				}
				Write-Detection $detection
			}
		}
	}
}

function Search-UtilmanHijack {
	# TODO - Add Better Details
	# Supports Drive Retargeting
	Write-Message "Checking utilman.exe"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
	if (Test-Path -Path $path) {
			$detection = [PSCustomObject]@{
				Name = 'Potential utilman.exe Registry Persistence'
				Risk = 'High'
				Source = 'Registry'
				Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
				Meta = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
			}
			Write-Detection $detection
	}
}

function Search-SethcHijack {
	# TODO - Add Better Details
	# Supports Drive Retargeting
	Write-Message "Checking sethc.exe"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
	if (Test-Path -Path $path) {
			$detection = [PSCustomObject]@{
				Name = 'Potential sethc.exe Registry Persistence'
				Risk = 'High'
				Source = 'Registry'
				Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
				Meta = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
			}
			Write-Detection $detection
	}
}