function Search-Connections {
	# Supports Dynamic Snapshotting
	# Does not support drive-retargeting
	if ($drivechange) {
		Write-Message "Skipping Network Connections - No Drive Retargeting"
		return
	}
	Write-Message "Checking Network Connections"
	$tcp_connections = Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, OwningProcess, RemoteAddress, RemotePort
	$suspicious_ports = @(20, 21, 22, 23, 25, 137, 139, 445, 3389, 443)
	$allow_listed_process_names = @(
		"brave",
		"chrome",
		"Discord",
		"firefox",
		"GitHubDesktop",
		"iexplorer",
		"msedge",
		"officeclicktorun"
		"OneDrive",
		"safari",
		"SearchApp",
		"Spotify",
		"steam"
	)
    
	foreach ($conn in $tcp_connections) {
		#allowlist_remote_addresses

		$proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue | Select-Object Name, Path

		Write-SnapshotMessage -Key $conn.RemoteAddress -Value $conn.RemoteAddress -Source 'Connections'

		if ($loadsnapshot -and (Confirm-IfAllowed $allowlist_remote_addresses $conn.RemoteAddress $conn.RemoteAddress)) {
			continue
		}

		if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024) {
			Write-SnapshotMessage -Key $proc.Name -Value $proc.Path -Source 'ProcessConnections'

			if ($loadsnapshot -and (Confirm-IfAllowed $allowlist_listeningprocs $proc.Name $proc.Path)) {
				continue
			}

			$detection = [PSCustomObject]@{
				Name      = 'Process Listening on Ephemeral Port'
				Risk      = 'Very Low'
				Source    = 'Network Connections'
				Technique = "T1071: Application Layer Protocol"
				Meta      = "Local Port: " + $conn.LocalPort + ", PID: " + $conn.OwningProcess + ", Process Name: " + $proc.Name + ", Process Path: " + $proc.Path
			}
			Write-Detection $detection
		}

		if ($conn.State -eq 'Established' -and ($conn.LocalPort -in $suspicious_ports -or $conn.RemotePort -in $suspicious_ports) -and $proc.Name -notin $allow_listed_process_names) {
			$detection = [PSCustomObject]@{
				Name      = 'Established Connection on Suspicious Port'
				Risk      = 'Low'
				Source    = 'Network Connections'
				Technique = "T1071: Application Layer Protocol"
				Meta      = "Local Port: " + $conn.LocalPort + ", Remote Port: " + $conn.RemotePort + ", Remote Address: " + $conn.RemoteAddress + ", PID: " + $conn.OwningProcess + ", Process Name: " + $proc.Name + ", Process Path: " + $proc.Path
			}
			Write-Detection $detection
		}

		if ($proc.Path) {
			if (Test-SuspiciousProcessPaths ($proc.Path).ToLower()) {
				$detection = [PSCustomObject]@{
					Name      = 'Process running from suspicious path has Network Connection'
					Risk      = 'High'
					Source    = 'Network Connections'
					Technique = "T1071: Application Layer Protocol"
					Meta      = "Local Port: " + $conn.LocalPort + ", Remote Port: " + $conn.RemotePort + ", Remote Address: " + $conn.RemoteAddress + ", PID: " + $conn.OwningProcess + ", Process Name: " + $proc.Name + ", Process Path: " + $proc.Path
				}
				Write-Detection $detection
			}
		}
	}
}