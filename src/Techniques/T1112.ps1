function Check-MicrosoftTelemetryCommands {
    # Supports Drive Retargeting
    Write-Message "Checking Microsoft TelemetryController"
    # Microsoft Telemetry Commands
    $allowed_telemetry_commands = @(
        "$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun"
        "$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun"
        "$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:UpdateAvStatus"
        "$env:systemroot\system32\CompatTelRunner.exe -m:devinv.dll -f:CreateDeviceInventory"
        "$env:systemroot\system32\CompatTelRunner.exe -m:pcasvc.dll -f:QueryEncapsulationSettings"
        "$env:systemroot\system32\CompatTelRunner.exe -m:invagent.dll -f:RunUpdate"
        "$env:systemroot\Windows\system32\CompatTelRunner.exe -m:generaltel.dll -f:DoCensusRun"

    )
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Command -ne $null){
                if ($data.Command -notin $allowed_telemetry_commands){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Microsoft Telemetry Command'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1112: Modify Registry"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryName = "Command"
                            EntryValue = $data.Command
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}

function Check-RemoteUACSetting {
    # Supports Drive Retargeting
    Write-Message "Checking RemoteUAC Setting"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'LocalAccountTokenFilterPolicy' -and $_.Value -eq 1) {
                $detection = [PSCustomObject]@{
                    Name = 'UAC Disabled for Remote Sessions'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1112: Modify Registry"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        EntryValue = $_.Value
                    }
                    Reference = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-PrintMonitorDLLs {
    # Supports Drive Retargeting
    Write-Message "Checking PrintMonitor DLLs"
    $standard_print_monitors = @(
		"APMon.dll",
		"AppMon.dll",
		"FXSMON.dll",
		"localspl.dll",
		"tcpmon.dll",
		"usbmon.dll",
		"WSDMon.dll" # Server 2016
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Monitors"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($data.Driver -notin $standard_print_monitors){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Monitor DLL'
                        Risk = 'Medium'
                        Source = 'Registry'
                        Technique = "T1112: Modify Registry"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryValue = $data.Driver
                            Hash = Get-File-Hash $data.Driver
                        }
                        Reference = "https://pentestlab.blog/2019/10/28/persistence-port-monitors/"
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}

function Check-NaturalLanguageDevelopmentDLLs {
    # Supports Drive Retargeting
    Write-Message "Checking NaturalLanguageDevelopment DLLs"
    $path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Control\ContentIndex\Language"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.StemmerDLLPathOverride -ne $null -or $data.WBDLLPathOverride -ne $null){
                if ($data.StemmerDLLPathOverride -ne $null){
                    $dll = $data.StemmerDLLPathOverride
                } elseif ($data.WBDLLPathOverride -ne $null){
                    $dll = $data.WBDLLPathOverride
                }
                $detection = [PSCustomObject]@{
                    Name = 'DLL Override on Natural Language Development Platform'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1112: Modify Registry"
                    Meta = [PSCustomObject]@{
                        Location = $item.Name
                        EntryValue = $dll
                        Hash = Get-File-Hash $dll
                    }
                    Reference = "https://persistence-info.github.io/Data/naturallanguage6.html"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-AMSIProviders {
    # Supports Drive Retargeting
    Write-Message "Checking AMSI Providers"
    $allowed_amsi_providers = @(
        "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
    )

    $path = "Registry::$regtarget_hklm`\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object *
        foreach ($item in $items) {
            if ($item.PSChildName -in $allowed_amsi_providers){
                continue
            }
            $new_path = "Registry::HKLM\SOFTWARE\Classes\CLSID\"+$item.PSChildName+"\InprocServer32"
            Write-Host $new_path
            if (Test-Path $new_path){
                $dll_data = Get-ItemProperty -Path $new_path
                $dll_data.PSObject.Properties | ForEach-Object {
                    if ($_.Name -in '(Default)'){
						Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AMSI'

                        $detection = [PSCustomObject]@{
                            Name = 'Non-Standard AMSI Provider DLL'
                            Risk = 'High'
                            Source = 'Registry'
                            Technique = "T1112: Modify Registry"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }

        }
    }
}

function Check-BootVerificationProgram {
    # Supports Drive Retargeting
    Write-Message "Checking BootVerificationProgram"
    $path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Control\BootVerificationProgram"
    if (Test-Path -Path $path) {
        $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        if ($data.ImagePath -ne $null){
            $detection = [PSCustomObject]@{
                Name = 'BootVerificationProgram will launch associated program as a service on startup.'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1112: Modify Registry"
                Meta = [PSCustomObject]@{
                    Location = $path
                    EntryName = $data.ImagePath
                    Hash = Get-File-Hash $data.ImagePath
                }
                Reference = "https://github.com/persistence-info/persistence-info.github.io/blob/main/Data/bootverificationprogram.md"
            }
            Write-Detection $detection
        }
    }
}