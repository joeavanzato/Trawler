function Check-Processes {
    # Does not support drive retargeting
    # TODO - Check for processes spawned from netsh.dll
    if ($drivechange){
        Write-Message "Skipping Process Analysis - No Drive Retargeting"
        return
    }

    Write-Message "Checking Running Processes"
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName,CreationDate,CommandLine,ExecutablePath,ParentProcessId,ProcessId
    foreach ($process in $processes){
        ForEach ($term in $rat_terms) {
            if ($process.CommandLine -match ".*$term.*") {
                $detection = [PSCustomObject]@{
                    Name = 'Running Process has known-RAT Keyword'
                    Risk = 'Medium'
                    Source = 'Processes'
                    Technique = "T1059: Command and Scripting Interpreter"
                    Meta = [PSCustomObject]@{
                        Location = $process.ExecutablePath
                        ProcessName = $process.ProcessName
                        CommandLine = $process.CommandLine
                        PID = $process.ProcessId
                        SuspiciousEntry = $term
                        Created = $process.CreationDate
                        Hash = Get-File-Hash $process.ExecutablePath
                    }
                }
                Write-Detection $detection
            }
        }
        if ($process.CommandLine -match $ipv4_pattern -or $process.CommandLine -match $ipv6_pattern) {
            $detection = [PSCustomObject]@{
                Name = 'IP Address Pattern detected in Process CommandLine'
                Risk = 'Medium'
                Source = 'Processes'
                Technique = "T1059: Command and Scripting Interpreter"
                Meta = [PSCustomObject]@{
                    Location = $process.ExecutablePath
                    ProcessName = $process.ProcessName
                    CommandLine = $process.CommandLine
                    PID = $process.ProcessId
                    Created = $process.CreationDate
                    Hash = Get-File-Hash $process.ExecutablePath
                }
            }
            Write-Detection $detection
        }
        foreach ($path in $suspicious_process_paths) {
            if ($process.ExecutablePath -match $path){
                $detection = [PSCustomObject]@{
                    Name = 'Suspicious Executable Path on Running Process'
                    Risk = 'High'
                    Source = 'Processes'
                    Technique = "T1059: Command and Scripting Interpreter"
                    Meta = [PSCustomObject]@{
                        Location = $process.ExecutablePath
                        ProcessName = $process.ProcessName
                        CommandLine = $process.CommandLine
                        PID = $process.ProcessId
                        Created = $process.CreationDate
                        Hash = Get-File-Hash $process.ExecutablePath
                    }
                }
                Write-Detection $detection
            }
        }

    }
}