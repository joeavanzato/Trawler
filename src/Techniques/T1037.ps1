function Search-Startups {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Startup Items"
	$paths = @(
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
	)

	if ($nevermind) {
		foreach ($tmpbase in $paths){
			if ($tmpbase -match "REPLACE.*"){
				foreach ($p in $regtarget_hkcu_list){
					$newpath = $tmpbase.Replace("REPLACE", $p)
					$paths += $newpath
				}
			}
		}
		$startups = @()
	} else {
		$startups = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command,Location,Name,User
		#$statups = @()

	}
	# Redoing this to only read reg-keys instead of using win32_StartupCommand
	foreach ($tmpbase in $paths){
		if ($tmpbase -match "REPLACE.*"){
			foreach ($p in $regtarget_hkcu_list){
				$newpath = $tmpbase.Replace("REPLACE", $p)
				$paths += $newpath
			}
		}
	}
	$startups = @()

	foreach ($item in $startups) {
		if ($loadsnapshot -and (Confirm-IfAllowed $allowlist_startup_commands $item.Command $item.Command)) {
			continue
		}

		Write-SnapshotMessage -Key $item.Name -Value $item.Command -Source 'Startup'

		$detection = [PSCustomObject]@{
			Name = 'Startup Item Review'
			Risk = 'Low'
			Source = 'Startup'
			Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
			Meta = "Location: "+$item.Location+", Item Name: "+$item.Name+", Command: "+$item.Command+", User: "+$item.User
		}

		Write-Detection $detection
	}

	foreach ($path_ in $paths){
		#Write-Host $path
		$path = "Registry::$path_"
		if (Test-Path -Path $path) {
			$item = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -ne "(Default)"){
					if ($loadsnapshot -and ($allowlist_startup_commands.Contains($_.Value))){
						continue
					}

					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'Startup'
					
					$detection = [PSCustomObject]@{
						Name = 'Startup Item Review'
						Risk = 'Low'
						Source = 'Startup'
						Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
						Meta = "Location: $path_, Item Name: "+$_.Name+", Command: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-GPOScripts {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking GPO Scripts"
	$base_key = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts"
	$script_paths = New-Object -TypeName "System.Collections.ArrayList"
	$homedrive = $env_homedrive
	$paths = @(
		"$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\User\Scripts\psscripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\User\Scripts\scripts.ini"
	)
	$path_lookup = @{
		Startup = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Startup\"
		Shutdown = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown\"
		Logoff = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logoff\"
		Logon = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logon\"
	}

	foreach ($path in $paths){
		# Skip non-existent files
		if(!(Test-Path $path)){
			return
		}
		
		$content = Get-Content $path
		$script_type = ""
		foreach ($line in $content){
			if ($line.Trim() -eq ""){
				continue
			}
			if ($line -eq "[Shutdown]"){
				$script_type = "Shutdown"
			} elseif ($line -eq "[Startup]"){
				$script_type = "Startup"
			} elseif ($line -eq "[Logon]"){
				$script_type = "Logon"
			} elseif ($line -eq "[Logoff]"){
				$script_type = "Logoff"
			} elseif ($line -match "\d{1,9}CmdLine="){
				$cmdline = $line.Split("=", 2)[1]
			} elseif ($line -match "\d{1,9}Parameters="){
				$params = $line.Split("=", 2)[1]
			}
			if ($params -ne $null){
				# Last line in each script descriptor is the Parameters
				if ($script_type -eq "Shutdown" -or $script_type -eq "Startup"){
					$desc = "Machine $script_type Script"
				} elseif ($script_type -eq "Logon" -or $script_paths -eq "Logoff"){
					$desc = "User $script_type Script"
				}

				$script_location = $cmdline
				if ($cmdline -notmatch "[A-Za-z]{1}:\\.*"){
					$script_location = $path_lookup[$script_type]+$cmdline
				}

				Write-SnapshotMessage -Key $script_location -Value $script_location -Source 'GPOScripts'

				$pass = $false
				if ($loadsnapshot){
					$result = Confirm-IfAllowed $allowlist_gposcripts $script_location $script_location
					if ($result){
						$cmdline = $null
						$params = $null
						continue
					}
				}
				# TODO - Figure out ERROR
				$script_content_detection = $false
				try {
					$script_content = Get-Content $script_location
					foreach ($line_ in $script_content){
						if (Test-TrawlerSuspiciousTerms $line_ -and $script_content_detection -eq $false){
							$detection = [PSCustomObject]@{
								Name = 'Suspicious Content in '+$desc
								Risk = 'High'
								Source = 'Windows GPO Scripts'
								Technique = "T1037: Boot or Logon Initialization Scripts"
								Meta = "File: "+$script_location+", Arguments: "+$params+", Suspicious Line: "+$line_
							}
							Write-Detection $detection
							$script_content_detection = $true
						}
					}
				} catch {
				}
				if ($script_content_detection -eq $false){
					$detection = [PSCustomObject]@{
						Name = 'Review: '+$desc
						Risk = 'Medium'
						Source = 'Windows GPO Scripts'
						Technique = "T1037: Boot or Logon Initialization Scripts"
						Meta = "File: "+$script_location+", Arguments: "+$params
					}
					Write-Detection $detection
				}
				$cmdline = $null
				$params = $null
			}

		}
	}
}

function Search-UserInitMPRScripts {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking UserInitMPRLogonScript"
	$basepath = "Registry::HKEY_CURRENT_USER\Environment"
	foreach ($p in $regtarget_hkcu_list){
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'UserInitMprLogonScript'){
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'UserInitMPR'

					if ($loadsnapshot){
						$result = Confirm-IfAllowed $allowlist_userinitmpr $_.Name $_.Value
						if ($result -eq $true){
							return
						}
					}
					$detection = [PSCustomObject]@{
						Name = 'Potential Persistence via Logon Initialization Script'
						Risk = 'Medium'
						Source = 'Registry'
						Technique = "T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)"
						Meta = "Key Location: HKCU\Environment, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Search-TerminalProfiles {
	# Supports Drive Retargeting
	# TODO - Snapshot/Allowlist specific exes
	Write-Message "Checking Terminal Profiles"
	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
	$base_path = "$env_homedrive\Users\_USER_\AppData\Local\Packages\"
	foreach ($user in $profile_names){
		$new_path = $base_path.replace("_USER_", $user.Name)
		$new_path += "Microsoft.WindowsTerminal*"
		$terminalDirs = Get-ChildItem $new_path -ErrorAction SilentlyContinue
		foreach ($dir in $terminalDirs){
			if (Test-Path "$dir\LocalState\settings.json"){
				$settings_data = Get-Content -Raw "$dir\LocalState\settings.json" | ConvertFrom-Json
				if ($settings_data.startOnUserLogin -eq $null -or $settings_data.startOnUserLogin -ne $true){
					continue
				}
				$defaultGUID = $settings_data.defaultProfile
				foreach ($profile_list in $settings_data.profiles){
					foreach ($profile in $profile_list.List){
						if ($profile.guid -eq $defaultGUID){
							if($profile.commandline){
								$exe = $profile.commandline
							} else {
								$exe = $profile.name
							}
							$detection = [PSCustomObject]@{
								Name = 'Windows Terminal launching command on login'
								Risk = 'Medium'
								Source = 'Terminal'
								Technique = "T1037: Boot or Logon Initialization Scripts"
								Meta = "File: $dir\LocalState\settings.json, Command: "+$exe
							}
							Write-Detection $detection
						}
					}
				}
			}
		}
	}
}