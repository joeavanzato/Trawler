function Search-AssociationHijack {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking File Associations"
	$homedrive = $env_assumedhomedrive
	$value_regex_lookup = @{
		accesshtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\MSACCESS.EXE`"";
		batfile = '"%1" %';
		certificate_wab_auto_file = "`"$homedrive\\Program Files\\Windows Mail\\wab.exe`" /certificate `"%1`"";
		"chm.file" = "`"$homedrive\\Windows\\hh.exe`" %1"
		cmdfile = '"%1" %';
		comfile = '"%1" %';
		desktopthemepackfile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1";
		evtfile = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
		evtxfile = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
		exefile = '"%1" %\*';
		hlpfile = "$homedrive\\Windows\\winhlp32.exe %1";
		mscfile = "$homedrive\\Windows\\system32\\mmc.exe `"%1`" %\*";
		powerpointhtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
		powerpointxmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
		prffile = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnPRF %1";
		ratfile = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnRAT %1";
		regfile = "regedit.exe `"%1`""
		scrfile = "`"%1`" /S"
		themefile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
		themepackfile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
		wbcatfile = "$homedrive\\Windows\\system32\\sdclt.exe /restorepage"
		wcxfile = "`"$homedrive\\Windows\\System32\\xwizard.exe`" RunWizard /u {.*} /z%1"
		"wireshark-capture-file" = "`"$homedrive\\.*\\Wireshark.exe`" `"%1`""
		wordhtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\WINWORD.EXE`""

	}
	# This specifically uses the list of CLASSES associated with each user, rather than the user hives directly
	$basepath = "Registry::HKEY_CURRENT_USER"
	foreach ($p in $regtarget_hkcu_class_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			foreach ($item in $items) {
				$path = $item.Name
				if ($path.EndsWith('file')){
					$basefile = $path.Split("\")[-1]
					$open_path = $path+"\shell\open\command"
					if (Test-Path -Path "Registry::$open_path"){
						$key = Get-ItemProperty -Path "Registry::$open_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
						$key.PSObject.Properties | ForEach-Object {
							if ($_.Name -eq '(default)'){
								#Write-Host $open_path $_.Value
								$exe = $_.Value
								$detection_triggered = $false
								Write-SnapshotMessage -Key $open_path -Value $exe -Source 'AssociationHijack'
								if ($loadsnapshot){
									$detection = [PSCustomObject]@{
										Name = 'Allowlist Mismatch: Possible File Association Hijack - Mismatch on Expected Value'
										Risk = 'Medium'
										Source = 'Registry'
										Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
										Meta = "FileType: " + $open_path +", Expected Association: "+ $allowtable_fileassocations[$open_path] + ", Current Association: " + $exe
									}
									$result = Confirm-IfAllowed $allowtable_fileassocations $open_path $exe $detection
									if ($result){
										continue
									}
								}

								if ($value_regex_lookup.ContainsKey($basefile)){
									if ($exe -notmatch $value_regex_lookup[$basefile]){
										$detection = [PSCustomObject]@{
											Name = 'Possible File Association Hijack - Mismatch on Expected Value'
											Risk = 'High'
											Source = 'Registry'
											Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
											Meta = "FileType: " + $open_path +", Expected Association: "+ $value_regex_lookup[$basefile] + ", Current Association: " + $exe
										}
										Write-Detection $detection
										return
									} else {
										return
									}
								}

								if ($exe -match ".*\.exe.*\.exe"){
									$detection = [PSCustomObject]@{
										Name = 'Possible File Association Hijack - Multiple EXEs'
										Risk = 'High'
										Source = 'Registry'
										Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
										Meta = "FileType: " + $open_path + ", Current Association: " + $exe
									}
									Write-Detection $detection
									return
								}
								if (Test-TrawlerSuspiciousTerms $exe){
									$detection = [PSCustomObject]@{
										Name = 'Possible File Association Hijack - Suspicious Keywords'
										Risk = 'High'
										Source = 'Registry'
										Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
										Meta = "FileType: " + $open_path + ", Current Association: " + $exe
									}
									Write-Detection $detection
								}
							}
						}
					}
				}
			}
		}
	}
	$basepath = "Registry::$regtarget_hklm`SOFTWARE\Classes"
	if (Test-Path -Path $basepath) {
		$items = Get-ChildItem -Path $basepath | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			$path = $item.Name
			if ($path.EndsWith('file')){
				$basefile = $path.Split("\")[-1]
				$open_path = $path+"\shell\open\command"
				if (Test-Path -Path "Registry::$open_path"){
					$key = Get-ItemProperty -Path "Registry::$open_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
					$key.PSObject.Properties | ForEach-Object {
						if ($_.Name -eq '(default)'){
							#Write-Host $open_path $_.Value
							$exe = $_.Value
							$detection_triggered = $false
							Write-SnapshotMessage -Key $open_path -Value $exe -Source 'AssociationHijack'

							if ($loadsnapshot){
								$detection = [PSCustomObject]@{
									Name = 'Allowlist Mismatch: Possible File Association Hijack - Mismatch on Expected Value'
									Risk = 'Medium'
									Source = 'Registry'
									Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
									Meta = "FileType: " + $open_path +", Expected Association: "+ $allowtable_fileassocations[$open_path] + ", Current Association: " + $exe
								}
								$result = Confirm-IfAllowed $allowtable_fileassocations $open_path $exe $detection
								if ($result){
									continue
								}
							}

							if ($value_regex_lookup.ContainsKey($basefile)){
								if ($exe -notmatch $value_regex_lookup[$basefile]){
									$detection = [PSCustomObject]@{
										Name = 'Possible File Association Hijack - Mismatch on Expected Value'
										Risk = 'High'
										Source = 'Registry'
										Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
										Meta = "FileType: " + $open_path +", Expected Association: "+ $value_regex_lookup[$basefile] + ", Current Association: " + $exe
									}
									Write-Detection $detection
									return
								} else {
									return
								}
							}

							if ($exe -match ".*\.exe.*\.exe"){
								$detection = [PSCustomObject]@{
									Name = 'Possible File Association Hijack - Multiple EXEs'
									Risk = 'High'
									Source = 'Registry'
									Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
									Meta = "FileType: " + $open_path + ", Current Association: " + $exe
								}
								Write-Detection $detection
								return
							}
							if (Test-TrawlerSuspiciousTerms $exe){
								$detection = [PSCustomObject]@{
									Name = 'Possible File Association Hijack - Suspicious Keywords'
									Risk = 'High'
									Source = 'Registry'
									Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
									Meta = "FileType: " + $open_path + ", Current Association: " + $exe
								}
								Write-Detection $detection
							}
						}
					}
				}
			}
		}
	}
}