function Check-DirectoryServicesRestoreMode {
    # Supports Retargeting
    Write-Message "Checking DirectoryServicesRestoreMode"
    $path = "$regtarget_hklm`System\CurrentControlSet\Control\Lsa"
    $path = "Registry::"+$path
    $data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
    $data.PSObject.Properties | ForEach-Object {
        if ($_.Name -eq 'DsrmAdminLogonBehavior' -and $_.Value -eq 2) {
            $detection = [PSCustomObject]@{
                Name = 'DirectoryServicesRestoreMode LocalAdmin Backdoor Enabled'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1003.003: OS Credential Dumping"
                Meta = [PSCustomObject]@{
                    Location = $path
                    EntryName = $_.Name
                    EntryValue = $_.Value
                }
                Reference = "https://adsecurity.org/?p=1785"
            }
            Write-Detection $detection
        }
    }
}