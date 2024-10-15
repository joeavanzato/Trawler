function Check-LNK {
    # Supports Drive Retargeting
    Write-Message "Checking LNK Targets"
    $current_date = Get-Date
    $WScript = New-Object -ComObject WScript.Shell
    $profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
    foreach ($user in $profile_names){
        $path = "$env_homedrive\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Windows\Recent"
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object {$_.extension -in ".lnk"} | Select-Object *
        foreach ($item in $items){
            #Write-Host $item.FullName, $item.LastWriteTime
            $lnk_target = $WScript.CreateShortcut($item.FullName).TargetPath
            $date_diff = $current_date - $item.LastWriteTime
            $comparison_timespan = New-TimeSpan -Days 90
            #Write-Host $date_diff.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
            $date_diff_temp = $comparison_timespan - $date_diff
            if ($date_diff_temp -ge 0){
                # If the LNK was modified within the last 90 days
                if ($lnk_target -match ".*\.exe.*\.exe.*"){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains multiple executables'
                        Risk = 'High'
                        Source = 'LNK'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = [PSCustomObject]@{
                            Location = $item.FullName
                            Created = $item.CreationTime
                            Modified = $item.LastWriteTime
                            LNKTarget = $lnk_target
                        }
                    }
                    Write-Detection $detection
                }
                if ($lnk_target -match $suspicious_terms){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains suspicious key-term'
                        Risk = 'High'
                        Source = 'LNK'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = [PSCustomObject]@{
                            Location = $item.FullName
                            Created = $item.CreationTime
                            Modified = $item.LastWriteTime
                            LNKTarget = $lnk_target
                        }
                    }
                    Write-Detection $detection
                }
                if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*"){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains multiple file extensions'
                        Risk = 'Medium'
                        Source = 'LNK'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = [PSCustomObject]@{
                            Location = $item.FullName
                            Created = $item.CreationTime
                            Modified = $item.LastWriteTime
                            LNKTarget = $lnk_target
                        }
                    }
                    Write-Detection $detection
                }

            }
        }
    }
}

function Check-ActiveSetup {
    # Supports Drive Retargeting
    Write-Message "Checking Active Setup Stubs"
    # T1547.014 - Boot or Logon Autostart Execution: Active Setup
    $standard_stubpaths = @(
		"/UserInstall",
		'"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', # Server 2016
		"$env_assumedhomedrive\Windows\System32\ie4uinit.exe -UserConfig", # 10
		"$env_assumedhomedrive\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install", # 10
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', # Server 2019
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', # Server 2019
		"$env_assumedhomedrive\Windows\System32\unregmp2.exe /FirstLogon", # 10
		"$env_assumedhomedrive\Windows\System32\unregmp2.exe /ShowWMP", # 10
        "$env_assumedhomedrive\Windows\System32\ie4uinit.exe -EnableTLS",
        "$env_assumedhomedrive\Windows\System32\ie4uinit.exe -DisableSSL3"
		"U"
        "regsvr32.exe /s /n /i:U shell32.dll"
        "$env_assumedhomedrive\Windows\system32\regsvr32.exe /s /n /i:/UserInstall C:\Windows\system32\themeui.dll"
        "$env_assumedhomedrive\Windows\system32\unregmp2.exe /FirstLogon /Shortcuts /RegBrowsers /ResetMUI"
    )
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Active Setup\Installed Components"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.StubPath -ne $null){
                if ($standard_stubpaths -notcontains $data.StubPath -and $data.StubPath -notmatch ".*(\\Program Files\\Google\\Chrome\\Application\\.*chrmstp.exe|Microsoft\\Edge\\Application\\.*\\Installer\\setup.exe).*"){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard StubPath Executed on User Logon'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.014: Boot or Logon Autostart Execution: Active Setup"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryName = "StubPath"
                            EntryValue = $data.StubPath
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}

function Check-WinlogonHelperDLLs {
    # Supports Drive Retargeting
    Write-Message "Checking Winlogon Helper DLLs"
    $standard_winlogon_helper_dlls = @(
        "C:\Windows\System32\userinit.exe,"
        "explorer.exe"
        "sihost.exe"
        "ShellAppRuntime.exe"
        "mpnotify.exe"
    )
    $path = "Registry::$regtarget_hklm`Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -in 'Userinit','Shell','ShellInfrastructure','ShellAppRuntime','MPNotify' -and $_.Value -notin $standard_winlogon_helper_dlls) {
                $detection = [PSCustomObject]@{
                    Name = 'Potential WinLogon Helper Persistence'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL"
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

function Check-LSA {
    # Supports Drive Retargeting
    Write-Message "Checking LSA DLLs"
    # LSA Security Package Review
    # TODO - Check DLL Modification/Creation times
    $common_ssp_dlls = @(
		"cloudAP", # Server 2016
		"ctxauth", #citrix
        "efslsaext.dll"
		"kerberos",
        "livessp",
        "lsasrv.dll"
		"msoidssp",
		"msv1_0",
		"negoexts",
		"pku2u",
		"schannel",
		"tspkg", # Server 2016
		"wdigest" # Server 2016
		"wsauth",
		"wsauth" #vmware
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                foreach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Security Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                                Hash = Get-File-Hash $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
            if ($_.Name -eq 'Authentication Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                foreach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Authentication Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.002: Boot or Logon Autostart Execution: Authentication Packages"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                                Hash = Get-File-Hash $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa\OSConfig"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                foreach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Security Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                                Hash = Get-File-Hash $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\LsaExtensionConfig\LsaSrv"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Extensions' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                foreach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Extensions Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                                Hash = Get-File-Hash $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }

    # T1556.002: Modify Authentication Process: Password Filter DLL
    # TODO - Check DLL Modification/Creation times
    $standard_lsa_notification_packages = @(
		"rassfm", # Windows Server 2019 AWS Lightsail
		"scecli" # Windows 10/Server
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "Notification Packages") {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                foreach ($package in $packages){
                    if ($package -notin $standard_lsa_notification_packages){
                        $detection = [PSCustomObject]@{
                            Name = 'Potential Exploitation via Password Filter DLL'
                            Risk = 'High'
                            Source = 'Registry'
                            Technique = "T1556.002: Modify Authentication Process: Password Filter DLL"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                                Hash = Get-File-Hash $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
}

function Check-TimeProviderDLLs {
    # Supports Drive Retargeting
    Write-Message "Checking Time Provider DLLs"
    $standard_timeprovider_dll = @(
        "$env:homedrive\Windows\System32\w32time.dll",
        "$env:homedrive\Windows\System32\vmictimeprovider.dll"
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Services\W32Time\TimeProviders"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.DllName -ne $null){
                if ($standard_timeprovider_dll -notcontains $data.DllName){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Time Providers DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.003: Boot or Logon Autostart Execution: Time Providers"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryValue = $data.DllName
                            Hash = Get-File-Hash $data.DllName
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}

function Check-PrintProcessorDLLs {
    # Supports Drive Retargeting
    Write-Message "Checking PrintProcessor DLLs"
    $standard_print_processors = @(
        "winprint.dll"
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Environments\Windows x64\Print Processors"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($standard_print_processors -notcontains $data.Driver){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Processor DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryValue = $data.Driver
                            Hash = Get-File-Hash $data.Driver
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Environments\Windows x64\Print Processors"
    if (Test-Path -Path $path) {
        $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($standard_print_processors -notcontains $data.Driver){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Processor DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
                        Meta = [PSCustomObject]@{
                            Location = $item.Name
                            EntryName = $data.Driver
                            Hash = Get-File-Hash $data.Driver
                        }
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}