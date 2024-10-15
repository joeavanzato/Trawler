function Check-Startups {
    # Supports Drive Retargeting
    Write-Message "Checking Startup Items"
    $paths = @(
        "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
        "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
        "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
        "REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        "REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        "REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
        "REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
        "REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
    )
    if ($nevermind) {
        foreach ($tmpbase in $paths){
            if ($tmpbase -match "REPLACE.*"){
                foreach ($p in $regtarget_hkcu_list){
                    $newpath = $tmpbase.Replace("REPLACE", $p)
                    $paths += $newpath
                }
            }
        }
        $startups = @()
    } else {
        $startups = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command,Location,Name,User
        #$statups = @()

    }
    # Redoing this to only read reg-keys instead of using win32_StartupCommand
    foreach ($tmpbase in $paths){
        if ($tmpbase -match "REPLACE.*"){
            foreach ($p in $regtarget_hkcu_list){
                $newpath = $tmpbase.Replace("REPLACE", $p)
                $paths += $newpath
            }
        }
    }
    $startups = @()

    foreach ($item in $startups) {
        $detection = [PSCustomObject]@{
            Name = 'Startup Item Review'
            Risk = 'Low'
            Source = 'Startup'
            Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
            Meta = [PSCustomObject]@{
                Location = $item.Location
                EntryName = $item.Name
                EntryValue = $item.Command
                User = $item.User
                Hash = Get-File-Hash $item.Location
            }
        }
        Write-Detection $detection
    }

    foreach ($path_ in $paths){
        #Write-Host $path
        $path = "Registry::$path_"
        if (Test-Path -Path $path) {
            $item = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $item.PSObject.Properties | ForEach-Object {
                if ($_.Name -ne "(Default)"){
                    $detection = [PSCustomObject]@{
                        Name = 'Startup Item Review'
                        Risk = 'Low'
                        Source = 'Startup'
                        Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
                        Meta = [PSCustomObject]@{
                            Location = $path_
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

    $startup_dir = "$env_assumedhomedrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    $startup_items = Get-ChildItem -Path $startup_dir -Recurse
    foreach ($file in $startup_items){
        $detection = [PSCustomObject]@{
            Name = 'Startup Item Review'
            Risk = 'Low'
            Source = 'Startup'
            Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
            Meta = [PSCustomObject]@{
                Location = $file.FullName
                Created = $file.CreationTime
                Modified = $file.LastWriteTime
                Hash = Get-File-Hash $file.FullName
            }
        }
        Write-Detection $detection
    }
}

function Check-GPO-Scripts {
    # Supports Drive Retargeting
    Write-Message "Checking GPO Scripts"
    $base_key = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts"
    $script_paths = New-Object -TypeName "System.Collections.ArrayList"
    $homedrive = $env_homedrive
    $paths = @(
        "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini",
        "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini",
        "$homedrive\Windows\System32\GroupPolicy\User\Scripts\psscripts.ini",
        "$homedrive\Windows\System32\GroupPolicy\User\Scripts\scripts.ini"
    )
    $path_lookup = @{
        Startup = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Startup\"
        Shutdown = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown\"
        Logoff = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logoff\"
        Logon = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logon\"
    }

    foreach ($path in $paths){
        # Skip non-existent files
        if((Test-Path $path) -eq $false){
            return
        }
        $content = Get-Content $path
        $script_type = ""
        foreach ($line in $content){
            if ($line.Trim() -eq ""){
                continue
            }
            if ($line -eq "[Shutdown]"){
                $script_type = "Shutdown"
            } elseif ($line -eq "[Startup]"){
                $script_type = "Startup"
            } elseif ($line -eq "[Logon]"){
                $script_type = "Logon"
            } elseif ($line -eq "[Logoff]"){
                $script_type = "Logoff"
            } elseif ($line -match "\d{1,9}CmdLine="){
                $cmdline = $line.Split("=", 2)[1]
            } elseif ($line -match "\d{1,9}Parameters="){
                $params = $line.Split("=", 2)[1]
            }
            if ($params -ne $null){
                # Last line in each script descriptor is the Parameters
                if ($script_type -eq "Shutdown" -or $script_type -eq "Startup"){
                    $desc = "Machine $script_type Script"
                } elseif ($script_type -eq "Logon" -or $script_paths -eq "Logoff"){
                    $desc = "User $script_type Script"
                }

                $script_location = $cmdline
                if ($cmdline -notmatch "[A-Za-z]{1}:\\.*"){
                    $script_location = $path_lookup[$script_type]+$cmdline
                }
                # TODO - Figure out ERROR
                $script_content_detection = $false
                try {
                    $script_content = Get-Content $script_location
                    foreach ($line_ in $script_content){
                        if ($line_ -match $suspicious_terms -and $script_content_detection -eq $false){
                            $detection = [PSCustomObject]@{
                                Name = 'Suspicious Content in '+$desc
                                Risk = 'High'
                                Source = 'Windows GPO Scripts'
                                Technique = "T1037: Boot or Logon Initialization Scripts"
                                Meta = [PSCustomObject]@{
                                    Location = $script_location
                                    EntryValue = $params
                                    SuspiciousEntry = $line_
                                }
                            }
                            Write-Detection $detection
                            $script_content_detection = $true
                        }
                    }
                } catch {
                }
                if ($script_content_detection -eq $false){
                    $detection = [PSCustomObject]@{
                        Name = 'Review: '+$desc
                        Risk = 'Medium'
                        Source = 'Windows GPO Scripts'
                        Technique = "T1037: Boot or Logon Initialization Scripts"
                        Meta = [PSCustomObject]@{
                            Location = $script_location
                            EntryValue = $params
                        }
                    }
                    Write-Detection $detection
                }
                $cmdline = $null
                $params = $null
            }

        }
    }

}

function Check-TerminalProfiles {
    # Supports Drive Retargeting
    Write-Message "Checking Terminal Profiles"
    $profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
    $base_path = "$env_homedrive\Users\_USER_\AppData\Local\Packages\"
    foreach ($user in $profile_names){
        $new_path = $base_path.replace("_USER_", $user.Name)
        $new_path += "Microsoft.WindowsTerminal*"
        $terminalDirs = Get-ChildItem $new_path -ErrorAction SilentlyContinue
        foreach ($dir in $terminalDirs){
            if (Test-Path "$dir\LocalState\settings.json"){
                $settings_data = Get-Content -Raw "$dir\LocalState\settings.json" | ConvertFrom-Json
                if ($settings_data.startOnUserLogin -eq $null -or $settings_data.startOnUserLogin -ne $true){
                    continue
                }
                $defaultGUID = $settings_data.defaultProfile
                foreach ($profile_list in $settings_data.profiles){
                    foreach ($profile in $profile_list.List){
                        if ($profile.guid -eq $defaultGUID){
                            if($profile.commandline){
                                $exe = $profile.commandline
                            } else {
                                $exe = $profile.name
                            }
                            $detection = [PSCustomObject]@{
                                Name = 'Windows Terminal launching command on login'
                                Risk = 'Medium'
                                Source = 'Terminal'
                                Technique = "T1037: Boot or Logon Initialization Scripts"
                                Meta = [PSCustomObject]@{
                                    Location = "$dir\LocalState\settings.json"
                                    EntryValue = $exe
                                }
                            }
                            Write-Detection $detection
                        }
                    }
                }
            }
        }
    }
}

function Check-UserInitMPRScripts {
    # Supports Drive Retargeting
    Write-Message "Checking UserInitMPRLogonScript"
    $basepath = "Registry::HKEY_CURRENT_USER\Environment"
    foreach ($p in $regtarget_hkcu_list){
        $path = $basepath.Replace("HKEY_CURRENT_USER", $p)
        if (Test-Path -Path $path) {
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq 'UserInitMprLogonScript'){
                    $detection = [PSCustomObject]@{
                        Name = 'Potential Persistence via Logon Initialization Script'
                        Risk = 'Medium'
                        Source = 'Registry'
                        Technique = "T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)"
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