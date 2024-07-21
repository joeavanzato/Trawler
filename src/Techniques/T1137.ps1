function Search-OfficeGlobalDotName {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Office GlobalDotName usage"
	# TODO - Cleanup Path Referencing, Add more versions?
	$office_versions = @(14,15,16)
	foreach ($version in $office_versions){
		$basepath = "Registry::HKEY_CURRENT_USER\software\microsoft\office\$version.0\word\options"
		foreach ($p in $regtarget_hkcu_list){
			$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
			if (Test-Path -Path $path) {
				$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
				$items.PSObject.Properties | ForEach-Object {
					if ($_.Name -eq "GlobalDotName"){
						Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'GlobalDotName'

						if ($loadsnapshot){
							$result = Confirm-IfAllowed $allowlist_globaldotname $_.Value $_.Value
							if ($result -eq $true){
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name = 'Persistence via Office GlobalDotName'
							Risk = 'Very High'
							Source = 'Office'
							Technique = "T1137.001: Office Application Office Template Macros"
							Meta = "Key Location: HKCU\software\microsoft\office\$version.0\word\options, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Search-Officetest {
	# Supports Drive Retargeting
	Write-Message "Checking Office test usage"
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
	foreach ($p in $regtarget_hkcu_list)
	{
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path)
		{
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				$detection = [PSCustomObject]@{
					Name = 'Persistence via Office test\Special\Perf Key'
					Risk = 'Very High'
					Source = 'Office'
					Technique = "T1137.002: Office Application Startup: Office Test"
					Meta = "Key Location: HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$path = "Registry::$regtarget_hklm`Software\Microsoft\Office test\Special\Perf"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		$items.PSObject.Properties | ForEach-Object {
			$detection = [PSCustomObject]@{
				Name = 'Persistence via Office test\Special\Perf Key'
				Risk = 'Very High'
				Source = 'Office'
				Technique = "T1137.002: Office Application Startup: Office Test"
				Meta = "Key Location: HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
			}
			Write-Detection $detection
		}
	}
}

function Search-OutlookStartup {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Outlook Macros"
	# allowlist_officeaddins
	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
	foreach ($user in $profile_names){
		$path = "$env_homedrive\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Word\STARTUP"
		$items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
		# Removing this as we are performing this functionality else-where for Office Trusted Location Scanning.
		#foreach ($item in $items){
		#	Write-SnapshotMessage -Key $item.FullName -Value $item.FullName -Source 'Office'

			# If the allowlist contains the curren task name
		#    if ($loadsnapshot -and ($allowlist_outlookstartup.Contains($item.FullName))){
		#        continue
		#    }

		#    $detection = [PSCustomObject]@{
		#        Name = 'Potential Persistence via Office Startup Addin'
		#        Risk = 'Medium'
		#        Source = 'Office'
		#        Technique = "T1137.006: Office Application Startup: Add-ins"
		#        Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
		#    }
			#Write-Detection $detection - Removing this as it is a duplicate of the new Office Scanning Functionality which will cover the same checks
		#}
		$path = "$env_homedrive\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
		if (Test-Path $path) {
			Write-SnapshotMessage -Key $path -Value $item.FullName -Source 'Outlook'

			if ($loadsnapshot -and (Confirm-IfAllowed $allowlist_outlookstartup $path $item.FullName)){
				continue
			}

			$detection = [PSCustomObject]@{
				Name = 'Potential Persistence via Outlook Application Startup'
				Risk = 'Medium'
				Source = 'Office'
				Technique = "T1137.006: Office Application Startup: Add-ins"
				Meta = "File: "+$path
			}
			Write-Detection $detection
		}
	}
}

function Search-OfficeTrustedLocations {
	# Supports Dynamic Snapshotting
	# Mostly supports drive retargeting
	# https://github.com/PowerShell/PowerShell/issues/16812
	Write-Message "Checking Office Trusted Locations"
	#TODO - Add 'abnormal trusted location' detection
	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
	$actual_current_user = $env:USERNAME
	$user_pattern = "$env_assumedhomedrive\\Users\\(.*?)\\.*"
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$possible_paths = New-Object -TypeName "System.Collections.ArrayList"
			foreach ($item in $items) {
				$path = "Registry::"+$item.Name
				$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
				if ($data.Path -ne $null){
					$possible_paths.Add($data.Path) | Out-Null
					$currentcaptureduser = [regex]::Matches($data.Path, $user_pattern).Groups.Captures.Value
					if ($currentcaptureduser -ne $null){
						$current_user = $currentcaptureduser[1]
					} else {
						$current_user = 'NO_USER_FOUND_IN_PATH'
					}
					if ($data.Path.Contains($current_user)){
						foreach ($user in $profile_names){
							$new_path = $data.Path.replace($current_user, $user.Name)
							#Write-Host $new_path
							if ($possible_paths -notcontains $new_path) {
								$possible_paths.Add($new_path) | Out-Null
							}
						}
					}


					$default_trusted_locations = @(
						"C:\Users\$actual_current_user\AppData\Roaming\Microsoft\Templates"
						"C:\Program Files\Microsoft Office\root\Templates\"
						"C:\Program Files (x86)\Microsoft Office\root\Templates\"
						"C:\Users\$actual_current_user\AppData\Roaming\Microsoft\Word\Startup"
					)
					$pass = $false
					Write-SnapshotMessage -Key $data.Path -Value $data.Path -Source 'OfficeTrustedLocations'

					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_office_trusted_locations $data.Path $data.Path
						if ($result){
							$pass = $true
						}
					}
					if ('{0}' -f $data.Path -notin $default_trusted_locations -and $pass -eq $false){
						$p = $data.Path
						$detection = [PSCustomObject]@{
							Name = 'Non-Standard Office Trusted Location'
							Risk = 'Medium'
							Source = 'Office'
							Technique = "T1137.006: Office Application Startup: Add-ins"
							Meta = "Location: $p"
						}
						Write-Detection $detection
						# TODO - Still working on this - can't read registry without expanding the variables right now
						# https://github.com/PowerShell/PowerShell/issues/16812
						#
					}
				}
			}
		}
	}

	foreach ($p in $possible_paths){
		if (Test-Path $p){
			$items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
			foreach ($item in $items){
				Write-SnapshotMessage -Key $item.FullName -Value $item.FullName -Source 'OfficeAddins'

				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_officeaddins $item.FullName $item.FullName
					if ($result){
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name = 'Potential Persistence via Office Startup Addin'
					Risk = 'Medium'
					Source = 'Office'
					Technique = "T1137.006: Office Application Startup: Add-ins"
					Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
				}
				Write-Detection $detection
			}
		}
	}
}