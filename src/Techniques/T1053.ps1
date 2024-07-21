function Search-ScheduledTasks {
	# Supports Dynamic Snapshotting for Executable Paths
	# Can possibly support drive-retargeting by parsing Task XML
	# Working on this with regex from Task Files
	# ^ Mostly working now
	# TODO - Add Argument Comparison Checks
	Write-Message "Checking Scheduled Tasks"

	$task_base_path = "$env_homedrive\Windows\System32\Tasks"
	$tasks = New-Object -TypeName "System.Collections.ArrayList"
	$author_pattern = '<Author>(?<Author>.*?)<\/Author>'
	$runas_pattern = '<Principal id="(?<RunAs>.*?)">'
	$execute_pattern = '<Command>(?<Execute>.*?)<\/Command>'
	$argument_pattern = '<Arguments>(?<Arguments>.*?)<\/Arguments>'
	$userid_pattern = '<UserId>(?<UserId>.*?)</UserId>'
	$sid_lookup = @{
		'S-1-5-17' = 'IUSR'
		'S-1-5-18' = 'SYSTEM'
		'S-1-5-19' = 'LOCAL_SERVICE'
		'S-1-5-20' = 'NETWORK_SERVICE'
	}

	if (Test-Path -Path $task_base_path) {
		$items = Get-ChildItem -Path $task_base_path -Recurse -ErrorAction SilentlyContinue
		foreach ($item in $items) {
			$task_content = Get-Content $item.FullName -ErrorAction SilentlyContinue | Out-String
			if ($task_content -eq $null) {
				continue
			}
			$task_content = [string]::join("", ($task_content.Split("`n")))
			#Write-Host $task_content[0]
			#$task_match = $regex_pattern.Match($task_content)

			$author_match = [regex]::Matches($task_content, $author_pattern)
			$runas_match = [regex]::Matches($task_content, $runas_pattern)
			$execute_match = [regex]::Matches($task_content, $execute_pattern)
			$arguments_match = [regex]::Matches($task_content, $argument_pattern)
			$userid_match = [regex]::Matches($task_content, $userid_pattern)


			If ($author_match[0] -eq $null) {
				$author = "N/A"
			}
			else {
				$author = $author_match[0].Groups["Author"].Value
			}
			If ($runas_match[0] -eq $null) {
				$runas = "N/A"
			}
			else {
				$runas = $runas_match[0].Groups["RunAs"].Value
				if ($runas -eq "Author") {
					$runas = $author
				}
			}
			If ($execute_match[0] -eq $null) {
				$execute = "N/A"
			}
			else {
				$execute = $execute_match[0].Groups["Execute"].Value
			}
			If ($arguments_match[0] -eq $null) {
				$arguments = "N/A"
			}
			else {
				$arguments = $arguments_match[0].Groups["Arguments"].Value
			}
			If ($userid_match[0] -eq $null) {
				$userid = $author
			}
			else {
				$userid = $userid_match[0].Groups["UserId"].Value
				if ($userid -eq 'System') {
					$userid = 'SYSTEM'
				}
				elseif ($userid -match 'S-.*') {
					if ($sid_lookup.ContainsKey($userid)) {
						$userid = $sid_lookup[$userid]
					}
				}
				if ($runas -eq 'N/A') {
					$runas = $userid
				}
				if ($author -eq 'N/A') {
					$author = $userid
				}
			}

			$task = [PSCustomObject]@{
				TaskName  = $item.Name
				Execute   = $execute
				Arguments = $arguments
				Author    = $author
				RunAs     = $runas
				UserId    = $userid
			}
			if ($task.Execute -ne "N/A") {
				$tasks.Add($task) | Out-Null
			}
		}
	}
 else {
		Write-Message "Could not find Scheduled Task Path: $task_base_path"
		return
	}

	$default_task_exe_paths = @(
		"`"%ProgramFiles%\Windows Media Player\wmpnscfg.exe`"",
		"%windir%\system32\appidpolicyconverter.exe",
		"%SystemRoot%\System32\ClipRenew.exe",
		"%SystemRoot%\System32\ClipUp.exe",
		"%SystemRoot%\System32\drvinst.exe",
		"%SystemRoot%\System32\dsregcmd.exe",
		"%SystemRoot%\System32\dusmtask.exe",
		"%SystemRoot%\System32\fclip.exe",
		"%SystemRoot%\System32\MbaeParserTask.exe",
		"%systemroot%\System32\MusNotification.exe",
		"%systemroot%\System32\sihclient.exe",
		"%systemroot%\System32\usoclient.exe",
		"%SystemRoot%\system32\Wat\WatAdminSvc.exe",
		"%SystemRoot%\System32\WiFiTask.exe",
		"%SystemRoot%\System32\wsqmcons.exe",
		"%windir%\System32\AppHostRegistrationVerifier.exe",
		"%windir%\System32\appidcertstorecheck.exe",
		"%windir%\System32\appidcertstorecheck.exe".
		"%windir%\System32\appidpolicyconverter.exe",
		"%windir%\System32\bcdboot.exe",
		"%windir%\System32\cleanmgr.exe",
		"%windir%\System32\compattelrunner.exe",
		"%windir%\System32\defrag.exe",
		"%windir%\System32\devicecensus.exe",
		"%windir%\System32\DFDWiz.exe",
		"%windir%\System32\directxdatabaseupdater.exe",
		"%windir%\System32\disksnapshot.exe",
		"%windir%\System32\dmclient.exe",
		"%windir%\System32\dstokenclean.exe",
		"%windir%\System32\dxgiadaptercache.exe",
		"%windir%\System32\eduprintprov.exe",
		"%windir%\System32\gatherNetworkInfo.vbs",
		"%windir%\System32\LocationNotificationWindows.exe",
		"%windir%\System32\lpremove.exe",
		"%windir%\system32\MDMAgent.exe",
		"%windir%\System32\ProvTool.exe",
		"%windir%\System32\RAServer.exe",
		"%windir%\System32\rundll32.exe",
		"%windir%\System32\sc.exe",
		"%SystemRoot%\system32\schtasks.exe",
		"%windir%\System32\SDNDiagnosticsTask.exe",
		"%WINDIR%\System32\SecureBootEncodeUEFI.exe",
		"%windir%\System32\ServerManagerLauncher.exe",
		"%windir%\System32\SpaceAgent.exe",
		"%windir%\System32\spaceman.exe",
		"%windir%\System32\speech_onecore\common\SpeechModelDownload.exe",
		"%windir%\System32\speech_onecore\common\SpeechRuntime.exe",
		"%windir%\System32\srtasks.exe",
		"%windir%\System32\srvinitconfig.exe",
		"%windir%\System32\tzsync.exe",
		"%windir%\System32\UNP\UpdateNotificationMgr.exe",
		"%windir%\System32\wermgr.exe",
		"%WinDir%\System32\WinBioPlugIns\FaceFodUninstaller.exe",
		"%windir%\System32\WindowsActionDialog.exe",
		"%windir%\System32\wpcmon.exe",
		"%windir%\System32\XblGameSaveTask.exe",
		"BthUdTask.exe",
		"$env_assumedhomedrive\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
		"$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe",
		"$env_assumedhomedrive\Program Files\Microsoft Office\root\Office16\sdxhelper.exe",
		"$env_assumedhomedrive\Program Files\Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16\operfmon.exe",
		"$env_assumedhomedrive\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe",
		"$env_assumedhomedrive\Program Files\NVIDIA Corporation\nview\nwiz.exe",
		"$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
		'"C:\Windows\System32\MicTray64.exe"',
		"$env_assumedhomedrive\Windows\System32\sc.exe",
		"`"$env_assumedhomedrive\Windows\System32\SynaMonApp.exe`"",
		"%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
		"$env:homedrive\WINDOWS\system32\msfeedssync.exe"
		"$env:homedrive\Program Files\Microsoft Security Client\MpCmdRun.exe"

	)

	$default_task_args = @(
		"config upnphost start= auto",
		'%systemroot%\System32\pla.dll,PlaHost "Server Manager Performance Monitor" "$(Arg0)"',
		'/B /nologo %systemroot%\System32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)',
		'/NoUACCheck'
	)
	#$tasks = Get-ScheduledTask  | Select-Object -Property State,Actions,Author,Date,Description,Principal,SecurityDescriptor,Settings,TaskName,TaskPath,Triggers,URI, @{Name="RunAs";Expression={ $_.principal.userid }} -ExpandProperty Actions | Select-Object *

	foreach ($task in $tasks) {
		# Allowlist Logic
		Write-SnapshotMessage -Key $task.TaskName -Value $task.Execute -Source "Scheduled Tasks"
		
		# If we are loading a snapshot allowlist
		# TODO - Compare Task Arguments for Changes
		if ($loadsnapshot) {
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch: Scheduled Task'
				Risk      = 'Medium'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
			}

			$result = Confirm-IfAllowed $allowtable_scheduledtask $task.TaskName $task.Execute $detection
			if ($result) {
				continue
			}
		}


		# Detection - Non-Standard Tasks
		foreach ($i in $default_task_exe_paths) {
			if ( $task.Execute -like $i) {
				$exe_match = $true
				break
			}
			elseif ($task.Execute.Length -gt 0) { 
				$exe_match = $false 
			}
		}

		if (Test-RemoteAccessTrojanTerms $task.Execute, $task.Arguments) {
			# Service has a suspicious launch pattern matching a known RAT
			$detection = [PSCustomObject]@{
				Name      = 'Scheduled Task has known-RAT Keyword'
				Risk      = 'Medium'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs + ", RAT Keyword: " + $term
			}
			Write-Detection $detection
		}
			
		# Task Running as SYSTEM
		if ($task.RunAs -eq "SYSTEM" -and $exe_match -eq $false -and $task.Arguments -notin $default_task_args) {
			# Current Task Executable Path is non-standard
			$detection = [PSCustomObject]@{
				Name      = 'Non-Standard Scheduled Task Running as SYSTEM'
				Risk      = 'High'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
			}
			Write-Detection $detection
			continue
		}
		# Detection - Task contains an IP Address
		if (Test-MatchIPAddress $task.Execute) {
			# Task Contains an IP Address
			$detection = [PSCustomObject]@{
				Name      = 'Scheduled Task contains an IP Address'
				Risk      = 'High'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
			}
			Write-Detection $detection
		}
		# TODO - Task contains domain-pattern

		# Task has suspicious terms
		$suspicious_keyword_regex = ".*(regsvr32.exe | downloadstring | mshta | frombase64 | tobase64 | EncodedCommand | DownloadFile | certutil | csc.exe | ieexec.exe | wmic.exe).*"
		if ($task.Execute -match $suspicious_keyword_regex -or $task.Arguments -match $suspicious_keyword_regex) {
			$detection = [PSCustomObject]@{
				Name      = 'Scheduled Task contains suspicious keywords'
				Risk      = 'High'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
			}
			Write-Detection $detection
		}
		# Detection - User Created Tasks
		if ($task.Author -ne $null) {
			if (($task.Author).Contains("\")) {
				if ((($task.Author.Split('\')).count - 1) -eq 1) {
					if ($task.RunAs -eq "SYSTEM") {
						# Current Task Executable Path is non-standard
						$detection = [PSCustomObject]@{
							Name      = 'User-Created Task running as SYSTEM'
							Risk      = 'High'
							Source    = 'Scheduled Tasks'
							Technique = "T1053: Scheduled Task/Job"
							Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
						}
						Write-Detection $detection
						continue
					}
					# Single '\' in author most likely indicates it is a user-made task
					$detection = [PSCustomObject]@{
						Name      = 'User Created Task'
						Risk      = 'Low'
						Source    = 'Scheduled Tasks'
						Technique = "T1053: Scheduled Task/Job"
						Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs
					}
					Write-Detection $detection
				}
			}
		}
		# Non-Standard EXE Path with Non-Default Argumentes
		if ($exe_match -eq $false -and $task.Arguments -notin $default_task_args) {
			# Current Task Executable Path is non-standard
			$detection = [PSCustomObject]@{
				Name      = 'Non-Standard Scheduled Task Executable'
				Risk      = 'Low'
				Source    = 'Scheduled Tasks'
				Technique = "T1053: Scheduled Task/Job"
				Meta      = "Task Name: " + $task.TaskName + ", Task Executable: " + $task.Execute + ", Arguments: " + $task.Arguments + ", Task Author: " + $task.Author + ", RunAs: " + $task.RunAs + ", UserId: " + $task.UserId
			}
			Write-Detection $detection
		}
	}
}