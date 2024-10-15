function Check-WSL {
    <#
    .SYNOPSIS
        Checks all installed WSL Virtual Machines and presents them for review, with an escalated risk if one is currently runnig
    #>
    Write-Message "Checking WSL"
    # This is some ugly code and I really do not like this implementation..but it works.
    # TODO - Check when wsl instance was created
    $output =  (wsl -l -v) -replace '\x00'
    if (-not ($output[0].Trim().StartsWith("NAME"))){
        Write-Host "WSL ERROR"
        return
    }
    foreach ($line in $output) {
        $line = $line.Trim()
        $line = $line.Trim("*")
        $line = $line.Trim()
        if ($line -eq "" -or $line.StartsWith("NAME")){
            continue
        }
        $data = $line.Split(" ")
        $components = @()
        foreach ($val in $data){
            $val = $val.Trim()
            if ($val -eq ""){
                continue
            }
            $components += $val

        }
        if ($components.Count -eq 3){
            $distro = $components[0]
            $status = $components[1]
            $version = $components[2]
            $detection = [PSCustomObject]@{
                Name = 'WSL Virtual Machine Exists'
                Risk = 'Low'
                Source = 'WSL'
                Technique = "T1564.006: Hide Artifacts: Run Virtual Instance"
                Meta = [PSCustomObject]@{
                    EntryName = $distro
                    Status = $status
                }
            }
            if ($status -eq "Running"){
                $detection.Name = "Running WSL Virtual Machine"
                $detection.Risk = "Medium"
                Write-Detection $detection
            } else {
                $detection.Name = "WSL Virtual Machine Existence"
                $detection.Risk = "Low"
                Write-Detection $detection
            }
        }

    }

}