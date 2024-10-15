function Check-Outlook-Startup {
    # Supports Drive Retargeting
    Write-Message "Checking Outlook Macros"
    # allowlist_officeaddins
    $profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
    foreach ($user in $profile_names){
        $path = "$env_homedrive\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Word\STARTUP"
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
        # Removing this as we are performing this functionality else-where for Office Trusted Location Scanning.
        #foreach ($item in $items){
		#	Write-SnapshotMessage -Key $item.FullName -Value $item.FullName -Source 'Office'

			# If the allowlist contains the curren task name
        #    if ($loadsnapshot -and ($allowlist_outlookstartup.Contains($item.FullName))){
        #        continue
        #    }

        #    $detection = [PSCustomObject]@{
        #        Name = 'Potential Persistence via Office Startup Addin'
        #        Risk = 'Medium'
        #        Source = 'Office'
        #        Technique = "T1137.006: Office Application Startup: Add-ins"
        #        Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
        #    }
            #Write-Detection $detection - Removing this as it is a duplicate of the new Office Scanning Functionality which will cover the same checks
        #}
        $path = "$env_homedrive\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
        if (Test-Path $path) {

            $i = Get-Item -Path $path -ErrorAction SilentlyContinue
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Outlook Application Startup'
                Risk = 'Medium'
                Source = 'Office'
                Technique = "T1137.006: Office Application Startup: Add-ins"
                Meta = [PSCustomObject]@{
                    Location = $path
                    Created = $i.CreationTime
                    Modified = $i.LastWriteTime
                }
            }
            Write-Detection $detection
        }
    }
}

function Check-OfficeTrustedDocuments {
    <#
    .SYNOPSIS
        Attempt to detect potentially-suspicious documents interacted with by the user.
    #>
    # When a user enables macros or creates a macro-enabled document, a reference to the document is stored at HKEY_CURRENT_USER\Software\Microsoft\Office\[office_version]\(Word|Excel|PowerPoint)\Security\Trusted Documents\TrustRecords
    # We can iterate this key to attempt and find any initial access related malware

    $basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords"
    $paths = Get-Item $basepath
    $reference = "https://www.bleepingcomputer.com/news/security/windows-registry-helps-find-malicious-docs-behind-infections/"
    # Last 4 bytes of "Data" will be 01 00 00 00 if we 'Enable Editing', FF FF FF 7F if we 'Enable Content'
    foreach ($path in $paths){
        $path = "Registry::$path"
        $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($prop in $data.psobject.Properties){
            [byte[]]$val = $prop.Value
            $hexbin = [System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::new()
            $hexbin.Value = $val
            $hexString = $hexbin.ToString()
            $macroEnabled = $false
            if ($hexString.EndsWith("FFFFFF7F")){
                $macroEnabled = $true
            }
            $Int64Value = [System.BitConverter]::ToInt64($prop.Value, 0)
            $date = [DateTime]::FromFileTime($Int64Value)
            if ($date.Year -eq 1600){
                $date = "Unknown"
            }
            $detection = [PSCustomObject]@{
                Name = 'Enable Content clicked on Office Document'
                Risk = 'Medium'
                Source = 'Office'
                Technique = "T1137.006: Office Application Startup: Add-ins"
                Meta = [PSCustomObject]@{
                    Location = $path
                    EntryName = $prop.Name
                    Created = $date
                }
            }
            if (-not $macroEnabled){
                $detection.Name = "Enable Editing clicked on Office Document"
                $detection.Risk = "Very Low"
            }
            Write-Detection $detection

        }
    }

}

function Check-Office-Trusted-Locations {
    # Mostly supports drive retargeting
    # https://github.com/PowerShell/PowerShell/issues/16812
    Write-Message "Checking Office Trusted Locations"
    #TODO - Add 'abnormal trusted location' detection
    # TODO - Redo this to consider all Office versions as well as Word, Excel and PowerPoint - need to abstract the logic better
    $profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
    $actual_current_user = $env:USERNAME
    $user_pattern = "$env_assumedhomedrive\\Users\\(.*?)\\.*"
    $basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations"
    foreach ($p in $regtarget_hkcu_list){
        $path = $basepath.Replace("HKEY_CURRENT_USER", $p)
        if (Test-Path -Path $path) {
            $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $possible_paths = New-Object -TypeName "System.Collections.ArrayList"
            foreach ($item in $items) {
                $path = "Registry::"+$item.Name
                $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
                if ($data.Path -ne $null){
                    $possible_paths.Add($data.Path) | Out-Null
                    $currentcaptureduser = [regex]::Matches($data.Path, $user_pattern).Groups.Captures.Value
                    if ($currentcaptureduser -ne $null){
                        $current_user = $currentcaptureduser[1]
                    } else {
                        $current_user = 'NO_USER_FOUND_IN_PATH'
                    }
                    if ($data.Path.Contains($current_user)){
                        foreach ($user in $profile_names){
                            $new_path = $data.Path.replace($current_user, $user.Name)
                            #Write-Host $new_path
                            if ($possible_paths -notcontains $new_path) {
                                $possible_paths.Add($new_path) | Out-Null
                            }
                        }
                    }

                    $default_trusted_locations = @(
                        ".*\\Users\\.*\\AppData\\Roaming\\Microsoft\\Templates"
                        ".*\\Program Files\\Microsoft Office\\root\\Templates\\"
                        ".*\\Program Files \(x86\)\\Microsoft Office\\root\\Templates\\"
                        ".*\\Users\\.*\\AppData\\Roaming\\Microsoft\\Word\\Startup"
                    )

                    $match = $false
                    foreach ($allowedpath in $default_trusted_locations){
                        if ($data.Path -match $allowedpath){
                            $match = $true
                        }
                    }

                    if (-not $match){
                        $p = $data.Path
                        $detection = [PSCustomObject]@{
                            Name = 'Non-Standard Office Trusted Location'
                            Risk = 'Medium'
                            Source = 'Office'
                            Technique = "T1137.006: Office Application Startup: Add-ins"
                            Meta = [PSCustomObject]@{
                                Location = $p
                            }
                        }
                        Write-Detection $detection
                        # TODO - Still working on this - can't read registry without expanding the variables right now
                        # https://github.com/PowerShell/PowerShell/issues/16812
                        #
                    }
                }
            }
        }
    }

    foreach ($p in $possible_paths){
        if (Test-Path $p){
            $items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
            foreach ($item in $items){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Persistence via Office Startup Addin'
                    Risk = 'Medium'
                    Source = 'Office'
                    Technique = "T1137.006: Office Application Startup: Add-ins"
                    Meta = [PSCustomObject]@{
                        Location = $item.FullName
                        Created =  $item.CreationTime
                        Modified = $item.LastWriteTime
                        Hash = Get-File-Hash $item.FullName
                    }
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-Officetest {
    # Supports Drive Retargeting
    Write-Message "Checking Office test usage"
    $basepath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
    foreach ($p in $regtarget_hkcu_list)
    {
        $path = $basepath.Replace("HKEY_CURRENT_USER", $p)
        if (Test-Path -Path $path)
        {
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
            $items.PSObject.Properties | ForEach-Object {
                $detection = [PSCustomObject]@{
                    Name = 'Persistence via Office test\Special\Perf Key'
                    Risk = 'Very High'
                    Source = 'Office'
                    Technique = "T1137.002: Office Application Startup: Office Test"
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
    $path = "Registry::$regtarget_hklm`Software\Microsoft\Office test\Special\Perf"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Persistence via Office test\Special\Perf Key'
                Risk = 'Very High'
                Source = 'Office'
                Technique = "T1137.002: Office Application Startup: Office Test"
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

function Check-OfficeGlobalDotName {
    # Supports Drive Retargeting
    Write-Message "Checking Office GlobalDotName usage"
    # TODO - Cleanup Path Referencing, Add more versions?
    $office_versions = @(14,15,16)
    foreach ($version in $office_versions){
        $basepath = "Registry::HKEY_CURRENT_USER\software\microsoft\office\$version.0\word\options"
        foreach ($p in $regtarget_hkcu_list){
            $path = $basepath.Replace("HKEY_CURRENT_USER", $p)
            if (Test-Path -Path $path) {
                $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
                $items.PSObject.Properties | ForEach-Object {
                    if ($_.Name -eq "GlobalDotName"){
                        $detection = [PSCustomObject]@{
                            Name = 'Persistence via Office GlobalDotName'
                            Risk = 'Very High'
                            Source = 'Office'
                            Technique = "T1137.001: Office Application Office Template Macros"
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