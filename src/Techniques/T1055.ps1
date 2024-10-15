function Check-DNSServerLevelPluginDLL {
    # Supports Drive Retargeting
    Write-Message "Checking DNSServerLevelPlugin DLL"
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Services\DNS\Parameters"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'ServerLevelPluginDll' -and $_.Value -ne '""') {
                $detection = [PSCustomObject]@{
                    Name = 'DNS ServerLevelPluginDLL is active'
                    Risk = 'Medium'
                    Source = 'Registry'
                    Technique = "T1055.001: Process Injection: Dynamic-link Library Injection"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        EntryValue = $_.Value
                        Hash = Get-File-Hash $_.Value
                    }
                }
                Write-Detection $detection
            }
        }
    }
}