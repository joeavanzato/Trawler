function Invoke-DriveChange {
	# HKLM associated hives detected on the target drive will be loaded as 'HKLM\ANALYSIS_$NAME' such as 'HKLM\ANALYSIS_SOFTWARE' for the SOFTWARE hive
	# User hives (NTUSER.DAT, USRCLASS.DAT) will be loaded as 'HKU\ANALYSIS_$NAME' and 'HKU\ANALYSIS_$NAME_Classes' respectively - such as 'HKU\ANALYSIS_JOE'/'HKU\ANALYSIS_JOE_Classes for each detected profile on the target drive.
	Write-Message "Setting up Registry Variables"
	if ($drivechange){
		Write-Host "[!] Moving Target Drive to $drivetarget"
		if ($drivetarget -notmatch "^[A-Za-z]{1}:$"){
			#Write-Warning "[!] Invalid Target Drive Format - should be in format like 'D:'"
			#exit
		}
		$dirs = Get-ChildItem $drivetarget -Attributes Directory | Select-Object *
		$windows_found = $false
		foreach ($dir in $dirs){
			if ($dir.Name -eq "Windows"){
				$windows_found = $true
				break
			}
		}
		if ($windows_found -eq $false){
			Write-Warning "[!] Could not find Windows Directory in Specified Target Path ($drivetarget)!"
			Write-Message "Make sure to specify ROOT directory containing imaged data (eg. 'F:')"
			exit
		}

		$script:env_homedrive = $drivetarget
		$script:env_assumedhomedrive = 'C:'
		$script:env_programdata = $drivetarget + "\ProgramData"
		$script:reg_target_hives = @(
			"SOFTWARE"
			"SYSTEM"
		)
		foreach ($hive in $reg_target_hives){
			$hive_path = "$env_homedrive\Windows\System32\Config\$hive"
			if (Test-Path $hive_path){
				Publish-Hive "ANALYSIS_$hive" $hive_path "HKEY_LOCAL_MACHINE"
			}
		}

		$script:reg_user_hives = @{}
		if (Test-Path "$env_homedrive\Users")
		{
			$user_hive_list = New-Object -TypeName "System.Collections.ArrayList"
			$user_hive_list_classes = New-Object -TypeName "System.Collections.ArrayList"
			$script:regtarget_hkcu_list = @()
			$script:regtarget_hkcu_class_list = @()
			$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
			foreach ($user in $profile_names){
				$name = $user.Name
				$ntuser_path = "$env_homedrive\Users\$name\NTUSER.DAT"
				$class_path = "$env_homedrive\Users\$name\AppData\Local\Microsoft\Windows\UsrClass.DAT"
				if (Test-Path $ntuser_path){
					$full_hive_path = "ANALYSIS_{0}" -f $name
					Publish-Hive $full_hive_path $ntuser_path "HKEY_USERS"
					$user_hive_list.Add($full_hive_path) | Out-Null
					$tmphivepath = "HKEY_USERS\$full_hive_path"
					$script:regtarget_hkcu_list += $tmphivepath
				}
				if (Test-Path $class_path){
					$full_hive_path = "ANALYSIS_{0}_Classes" -f $name
					Publish-Hive $full_hive_path $class_path "HKEY_USERS"
					$user_hive_list_classes.Add($full_hive_path) | Out-Null
					$tmphivepath = "HKEY_USERS\$full_hive_path"
					$script:regtarget_hkcu_class_list += $tmphivepath
				}

			}

		} else {
			$profile_names = @()
			Write-Warning "[!] Could not find '$env_homedrive\Users'!"
		}

		$script:regtarget_hklm = "HKEY_LOCAL_MACHINE\ANALYSIS_"
		$script:regtarget_hkcu = "HKEY_CURRENT_USER\"
		# Need to avoid using HKCR as it will be unavailable on dead drives
		$script:regtarget_hkcr = "HKEY_CLASSES_ROOT\"
		$script:currentcontrolset = "ControlSet001"


	} elseif ($drivechange -eq $false){
		# Load all HKU hives into lists for global reference
		$script:regtarget_hkcu_list = @()
		$script:regtarget_hkcu_class_list = @()
		$base_key = "HKEY_USERS"
		$items = Get-ChildItem -Path "Registry::$base_key" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
		foreach ($item in $items) {
			if ($item.Name -match ".*_Classes"){
				$script:regtarget_hkcu_class_list += $item.Name
			} else {
				$script:regtarget_hkcu_list += $item.Name
			}
		}
		$script:env_homedrive = $env:homedrive
		$script:env_assumedhomedrive = $env:homedrive
		$script:env_programdata = $env:programdata
		$script:regtarget_hklm = "HKEY_LOCAL_MACHINE\"
		$script:regtarget_hkcu = "HKEY_CURRENT_USER\"
		# Need to avoid using HKCR as it will be unavailable on dead drives
		$script:regtarget_hkcr = "HKEY_CLASSES_ROOT\"
		$script:currentcontrolset = "CurrentControlSet"
	}

}

$new_psdrives_list = @{}
function Publish-Hive($hive_name, $hive_path, $hive_root) {
	Write-Message "Loading Registry Hive File: $hive_path at location: $hive_root\$hive_name"
	$null = New-PSDrive -PSProvider Registry -Name $hive_name -Root $hive_root
	$reg_fullpath = "$hive_root`\$hive_name"
	$null = reg load $reg_fullpath "$hive_path"
	$new_psdrives_list.Add($reg_fullpath, $hive_name)
}

function Unpublish-Hive($hive_fullpath, $hive_value){
	Write-Message "Unloading $hive_fullpath"
	[gc]::collect()
	$null = reg unload $hive_fullpath
	#$null = Remove-PSDrive -Name $hive_value -Root $hive_root
}