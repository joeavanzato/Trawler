function Search-PowerShellProfiles {
	# PowerShell profiles may be abused by adversaries for persistence.
	# Supports Drive Retargeting
	# TODO - Add check for 'suspicious' content
	# TODO - Consider allow-listing here

	# $PSHOME\Profile.ps1
	# $PSHOME\Microsoft.PowerShell_profile.ps1
	# $HOME\Documents\PowerShell\Profile.ps1
	# $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
	Write-Message "Checking PowerShell Profiles"
	if ($drivechange){
		# TODO - Investigate whether these paths can be retrieved from the HKLM HIVE dynamically
		$alluserallhost = "$env_homedrive\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
		$allusercurrenthost =  "$env_homedrive\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1"
	} else {
		$PROFILE | Select-Object AllUsersAllHosts,AllUsersCurrentHost,CurrentUserAllHosts,CurrentUserCurrentHost | Out-Null
		$alluserallhost = $PROFILE.AllUsersAllHosts
		$allusercurrenthost = $PROFILE.AllUsersCurrentHost
	}

	if (Test-Path $alluserallhost){
		$detection = [PSCustomObject]@{
			Name = 'Review: Global Custom PowerShell Profile'
			Risk = 'Medium'
			Source = 'PowerShell'
			Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
			Meta = "Profile: "+$PROFILE.AllUsersAllHosts
		}
		Write-Detection $detection
	}
	if (Test-Path $allusercurrenthost){
		$detection = [PSCustomObject]@{
			Name = 'Review: Global Custom PowerShell Profile'
			Risk = 'Medium'
			Source = 'PowerShell'
			Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
			Meta = "Profile: "+$PROFILE.AllUsersCurrentHost
		}
		Write-Detection $detection
	}

	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object Name
	foreach ($name in $profile_names){
		$path1 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\profile.ps1"
		$path2 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
		$path3 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
		if (Test-Path $path1){
			$detection = [PSCustomObject]@{
				Name = 'Review: Custom PowerShell Profile'
				Risk = 'Medium'
				Source = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta = "Profile: "+$path1
			}
			Write-Detection $detection
		}
		if (Test-Path $path2){
			$detection = [PSCustomObject]@{
				Name = 'Review: Custom PowerShell Profile'
				Risk = 'Medium'
				Source = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta = "Profile: "+$path2
			}
			Write-Detection $detection
		}
		if (Test-Path $path3){
			$detection = [PSCustomObject]@{
				Name = 'Review: Custom PowerShell Profile'
				Risk = 'Medium'
				Source = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta = "Profile: "+$path3
			}
			Write-Detection $detection
		}
	}
}
