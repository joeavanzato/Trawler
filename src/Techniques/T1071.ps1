function Check-Connections {
    # Does not support drive-retargeting
    if ($drivechange){
        Write-Message "Skipping Network Connections - No Drive Retargeting"
        return
    }
    Write-Message "Checking Network Connections"
    $tcp_connections = Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort
    $suspicious_ports = @(20,21,22,23,25,137,139,445,3389,443)
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

        if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024){
            $detection = [PSCustomObject]@{
                Name = 'Process Listening on Ephemeral Port'
                Risk = 'Very Low'
                Source = 'Network Connections'
                Technique = "T1071: Application Layer Protocol"
                Meta = [PSCustomObject]@{
                    Location = $proc.Path
                    ProcessName = $proc.Name
                    PID = $conn.OwningProcess
                    LocalPort = $conn.LocalPort
                }
            }
            Write-Detection $detection
        }
        if ($conn.State -eq 'Established' -and ($conn.LocalPort -in $suspicious_ports -or $conn.RemotePort -in $suspicious_ports) -and $proc.Name -notin $allow_listed_process_names){
            $detection = [PSCustomObject]@{
                Name = 'Established Connection on Suspicious Port'
                Risk = 'Low'
                Source = 'Network Connections'
                Technique = "T1071: Application Layer Protocol"
                Meta = [PSCustomObject]@{
                    Location = $proc.Path
                    ProcessName = $proc.Name
                    PID = $conn.OwningProcess
                    LocalPort = $conn.LocalPort
                    LocalAddress = $conn.LocalAddress
                    RemotePort = $conn.RemotePort
                    RemoteAddress = $conn.RemoteAddress
                }
            }
            Write-Detection $detection
        }
        if ($proc.Path -ne $null){
            foreach ($path in $suspicious_process_paths){
                if (($proc.Path).ToLower() -match $path){
                    $detection = [PSCustomObject]@{
                        Name = 'Process running from suspicious path has Network Connection'
                        Risk = 'High'
                        Source = 'Network Connections'
                        Technique = "T1071: Application Layer Protocol"
                        Meta = [PSCustomObject]@{
                            Location = $proc.Path
                            ProcessName = $proc.Name
                            PID = $conn.OwningProcess
                            LocalPort = $conn.LocalPort
                            LocalAddress = $conn.LocalAddress
                            RemotePort = $conn.RemotePort
                            RemoteAddress = $conn.RemoteAddress
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}