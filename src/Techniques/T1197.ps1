function Check-BITS {
    # Maybe with Drive Retargeting
    # C:\ProgramData\Microsoft\Network\Downloader
    # https://www.giac.org/paper/gcih/28198/bits-forensics/130713#:~:text=These%20files%20are%20named%20%E2%80%9Cqmgr0,Microsoft%5CNetwork%5CDownloader%E2%80%9D.
    if ($drivechange){
        Write-Message "Skipping BITS Analysis - No Drive Retargeting [yet]"
        return
    }
    Write-Message "Checking BITS Jobs"
    $bits = Get-BitsTransfer -AllUsers | Select-Object *
    foreach ($item in $bits) {
        if ($item.NotifyCmdLine -ne $null){
            $cmd = [string]$item.NotifyCmdLine
        } else {
            $cmd = ''
        }
        $detection = [PSCustomObject]@{
            Name = 'BITS Item Review'
            Risk = 'Low'
            Source = 'BITS'
            Technique = "T1197: BITS Jobs"
            Meta = [PSCustomObject]@{
                EntryName = $item.DisplayName
                TransferType = $item.TransferType
                JobState = $item.JobState
                User = $item.OwnerAccount
                EntryValue = $cmd
            }
        }
        Write-Detection $detection
    }
}