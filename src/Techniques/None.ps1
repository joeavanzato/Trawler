function Search-SuspiciousFileLocations {
	Write-Message "Checking Suspicious File Locations"
	$suspicious_extensions = @('*.exe', '*.bat', '*.ps1', '*.hta', '*.vb', '*.vba', '*.vbs', '*.zip', '*.gz', '*.7z', '*.dll', '*.scr', '*.cmd', '*.com', '*.ws', '*.wsf', '*.scf', '*.scr', '*.pif')
	$recursive_paths_to_check = @(
		"$env_homedrive\Users\Public"
		"$env_homedrive\Users\Administrator"
		"$env_homedrive\Windows\temp"
	)
	foreach ($path in $recursive_paths_to_check){
		$items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Include $suspicious_extensions
		foreach ($item in $items){
			$detection = [PSCustomObject]@{
				Name = 'Anomalous File in Suspicious Location'
				Risk = 'High'
				Source = 'Windows'
				Technique = "N/A"
				Meta = "File: "+$item.FullName+", Created: "+$item.CreationTime+", Last Modified: "+$item.LastWriteTime
			}
			Write-Detection $detection
		}
	}
}

function Search-SCM-DACL {
	# https://pentestlab.blog/2023/03/20/persistence-service-control-manager/
	# TODO
}