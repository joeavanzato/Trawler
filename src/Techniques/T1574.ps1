function Check-Process-Modules {
    # Does not support Drive Retargeting
    if ($drivechange){
        Write-Message "Skipping Phantom DLLs - No Drive Retargeting"
        return
    }
    Write-Message "Checking 'Phantom' DLLs"
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName,CreationDate,CommandLine,ExecutablePath,ParentProcessId,ProcessId
    $suspicious_unsigned_dll_names = @(
        "cdpsgshims.dll",
        "diagtrack_win.dll",
        "EdgeGdi.dll",
        "Msfte.dll",
        "phoneinfo.dll",
        "rpcss.dll",
        "sapi_onecore.dll",
        "spreview.exewdscore.dll",
        "Tsmsisrv.dll",
        "TSVIPSrv.dll",
        "Ualapi.dll",
        "UsoSelfhost.dll",
        "wbemcomn.dll",
        "WindowsCoreDeviceInfo.dll",
        "windowsperformancerecordercontrol.dll",
        "wlanhlp.dll",
        "wlbsctrl.dll",
        "wow64log.dll",
        "WptsExtensions.dll",
        "oci.dll",
        "TPPCOIPW32.dll",
        "tpgenlic.dll",
        "thinmon.dll",
        "fxsst.dll",
        "msTracer.dll",
        "fveapi.dll"
    )
    $allowlist = @(
        ".*\\Windows\\(SYSTEM32|SysWOW64)\\(wbemcomn|rpcss|FVEAPI|wlanhlp|windowsperformancerecordercontrol)\.dll",
        ".*\\Windows\\System32\\Speech_OneCore\\Common\\sapi_onecore\.dll"
    )
    foreach ($process in $processes){
        $modules = Get-Process -id $process.ProcessId -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty modules -ErrorAction SilentlyContinue | Select-Object Company,FileName,ModuleName
        if ($modules -ne $null){
            foreach ($module in $modules){
                if ($module.ModuleName -in $suspicious_unsigned_dll_names) {
                    $signature = Get-AuthenticodeSignature $module.FileName
                    $item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
                    $match = $false
                    foreach ($alloweditem in $allowlist){
                        if ($module.FileName -match $alloweditem){
                            $match = $true
                        }
                    }
                    if ($match){
                        continue
                    }

                    if ($signature.Status -ne 'Valid'){
                        $detection = [PSCustomObject]@{
                            Name = 'Suspicious Unsigned DLL with commonly-masqueraded name loaded into running process.'
                            Risk = 'Very High'
                            Source = 'Processes'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = [PSCustomObject]@{
                                Location = $module.FileName
                                Created = $item.CreationTime
                                Modified = $item.LastWriteTime
                                ProcessName = $process.ProcessName
                                PID = $process.ProcessId
                                Executable = $process.ExecutablePath
                                Hash = Get-File-Hash $module.FileName
                            }
                        }
                        Write-Detection $detection
                    } else {
                        if ($signature.SignerCertificate.SubjectName.Name -match "(.*Microsoft Windows.*|.*Microsoft Corporation.*|.*Microsoft Windows Publisher.*)"){
                            continue
                        }
                        $detection = [PSCustomObject]@{
                            Name = 'Suspicious DLL with commonly-masqueraded name loaded into running process.'
                            Risk = 'High'
                            Source = 'Processes'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = [PSCustomObject]@{
                                Location = $module.FileName
                                Created = $item.CreationTime
                                Modified = $item.LastWriteTime
                                ProcessName = $process.ProcessName
                                PID = $process.ProcessId
                                Executable = $process.ExecutablePath
                                Hash = Get-File-Hash $module.FileName
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
}

function Check-Windows-Unsigned-Files {
    # Supports Drive Retargeting - Not actually sure if this will work though
    Write-Message "Checking Unsigned Files"
    $scan_paths = @(
    "$env_homedrive\Windows",
    "$env_homedrive\Windows\System32",
    "$env_homedrive\Windows\System"
    "$env_homedrive\Windows\temp"
    )
    #allowlist_unsignedfiles
    foreach ($path in $scan_paths)
    {
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".dll", ".exe" } | Select-Object *
        foreach ($file in $files)
        {
            $sig = Get-AuthenticodeSignature $file.FullName
            if ($sig.Status -ne 'Valid')
            {
                $item = Get-ChildItem -Path $file.FullName -File -ErrorAction SilentlyContinue | Select-Object *
                $detection = [PSCustomObject]@{
                    Name = 'Unsigned DLL/EXE present in critical OS directory'
                    Risk = 'Very High'
                    Source = 'Windows'
                    Technique = "T1574: Hijack Execution Flow"
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
    }
}

function Check-Service-Hijacks {
    Write-Message "Checking Un-Quoted Services"
    # Supports Drive Retargeting, assumes homedrive is C:
    #$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
    $service_path = "$regtarget_hklm`SYSTEM\$currentcontrolset\Services"
    $service_list = New-Object -TypeName "System.Collections.ArrayList"
    if (Test-Path -Path "Registry::$service_path") {
        $items = Get-ChildItem -Path "Registry::$service_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        foreach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSProvider
            if ($data.ImagePath -ne $null){
                $service = [PSCustomObject]@{
                    Name = $data.PSChildName
                    PathName = $data.ImagePath
                }
                $service.PathName = $service.PathName.Replace("\SystemRoot", "$env_assumedhomedrive\Windows")
                $service_list.Add($service) | Out-Null
            }
        }
    }
    foreach ($service in $service_list){
        $service.PathName = ($service.PathName).Replace("C:", $env_homedrive)
        if ($service.PathName -match '".*"[\s]?.*') {
            # Skip Paths where the executable is contained in quotes
            continue
        }
        # Is there a space in the service path?
        if ($service.PathName.Contains(" ")) {
            $original_service_path = $service.PathName
            # Does the path contain a space before the exe?
            if ($original_service_path -match '.*\s.*\.exe.*'){
                $tmp_path = $original_service_path.Split(" ")
                $base_path = ""
                foreach ($path in $tmp_path){
                    $base_path += $path
                    $test_path = $base_path + ".exe"
                    if (Test-Path $test_path) {
                        $detection = [PSCustomObject]@{
                            Name = 'Possible Service Path Hijack via Unquoted Path'
                            Risk = 'High'
                            Source = 'Services'
                            Technique = "T1574.009: Create or Modify System Process: Windows Service"
                            Meta = [PSCustomObject]@{
                                Location = $test_path
                                ServiceName = $service.Name
                                ServicePath = $service.PathName
                                Hash = Get-File-Hash $test_path
                            }
                        }
                        Write-Detection $detection
                    }
                    $base_path += " "
                }
            }
        }
    }
}

function Check-PATH-Hijacks {
    # Mostly supports drive retargeting - assumed PATH is prefixed with C:
    # Data Stored at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment
    # Can just collect from this key instead of actual PATH var
    Write-Message "Checking PATH Hijacks"
    $system32_path = "$env_homedrive\windows\system32"
    $system32_bins = Get-ChildItem -File -Path $system32_path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object Name
    $sys32_bins = New-Object -TypeName "System.Collections.ArrayList"

    foreach ($bin in $system32_bins){
        $sys32_bins.Add($bin.Name) | Out-Null
    }
    $path_reg = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Session Manager\Environment"
    if (Test-Path -Path $path_reg) {
        $items = Get-ItemProperty -Path $path_reg | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "Path") {
                $path_entries = $_.Value
            }
        }
    }
    $path_entries = $path_entries.Split(";")
    $paths_before_sys32 = New-Object -TypeName "System.Collections.ArrayList"
    foreach ($path in $path_entries){
        $path = $path.Replace("C:", $env_homedrive)
        if ($path -ne $system32_path){
            $paths_before_sys32.Add($path) | Out-Null
        } else {
            break
        }
    }

    foreach ($path in $paths_before_sys32){
        $path_bins = Get-ChildItem -File -Path $path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object *
        foreach ($bin in $path_bins){
            if ($bin.Name -in $sys32_bins){
                $detection = [PSCustomObject]@{
                    Name = 'Possible PATH Binary Hijack - same name as SYS32 binary in earlier PATH entry'
                    Risk = 'Very High'
                    Source = 'PATH'
                    Technique = "T1574.007: Hijack Execution Flow: Path Interception by PATH Environment Variable"
                    Meta = [PSCustomObject]@{
                        Location = $bin.FullName
                        Created = $bin.CreationTime
                        Modified = $bin.LastWriteTime
                        Hash = Get-File-Hash $bin.FullName
                    }
                }
                Write-Detection $detection
            }
        }

    }
}

function Check-PeerDistExtensionDll {
    # Supports Drive Targeting
    Write-Message "Checking PeerDistExtension DLL"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension"
    $expected_value = "peerdist.dll"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "PeerdistDllName" -and $_.Value -ne $expected_value) {
                $detection = [PSCustomObject]@{
                    Name = 'PeerDist DLL does not match expected value'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        EntryValue = $_.Value
                        ExpectedValue = $expected_value
                        Hash = Get-File-Hash $_.Value
                    }
                    Reference = "https://www.hexacorn.com/blog/2022/01/23/beyond-good-ol-run-key-part-138/"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-InternetSettingsLUIDll {
    # Supports Drive Retargeting
    Write-Message "Checking InternetSettings DLL"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\LUI"
    $expected_value = "$env_assumedhomedrive\Windows\system32\wininetlui.dll!InternetErrorDlgEx"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "0" -and $_.Value -ne $expected_value) {
                $detection = [PSCustomObject]@{
                    Name = 'InternetSettings LUI Error DLL does not match expected value'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        EntryValue = $_.Value
                        ExpectedValue = $expected_value
                        Hash = Get-File-Hash $_.Value
                    }
                    Reference = "https://www.hexacorn.com/blog/2022/01/22/beyond-good-ol-run-key-part-137/"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-ErrorHandlerCMD {
    # Support Drive Retargeting
    Write-Message "Checking ErrorHandler.cmd"
    $path = "$env_homedrive\windows\Setup\Scripts\ErrorHandler.cmd"
    if (Test-Path $path){

        $script_content_detection = $false
        try {
            $script_content = Get-Content $path
            foreach ($line_ in $script_content){
                if ($line_ -match $suspicious_terms -and $script_content_detection -eq $false){
                    $detection = [PSCustomObject]@{
                        Name = 'Suspicious Content in ErrorHandler.cmd'
                        Risk = 'High'
                        Source = 'Windows'
                        Technique = "T1574: Hijack Execution Flow"
                        Meta = [PSCustomObject]@{
                            Location = $path
                            EntryValue = $line_
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
                Name = 'Review: ErrorHandler.cmd Existence'
                Risk = 'High'
                Source = 'Windows'
                Technique = "T1574: Hijack Execution Flow"
                Meta = [PSCustomObject]@{
                    Location = $path
                }
            }
            Write-Detection $detection
        }
    }
}

function Check-BIDDll {
    # Can support drive retargeting
    Write-Message "Checking BID DLL"
    $paths = @(
        "Registry::$regtarget_hklm`Software\Microsoft\BidInterface\Loader"
        "Registry::$regtarget_hklm`software\Wow6432Node\Microsoft\BidInterface\Loader"

    )
    $expected_values = @(
        "$env:homedrive\\Windows\\Microsoft\.NET\\Framework\\.*\\ADONETDiag\.dll"
        "$env:homedrive\\Windows\\SYSTEM32\\msdaDiag\.dll"

    )
    foreach ($path in $paths){
        if (Test-Path -Path $path) {
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq ":Path") {
                    $match = $false
                    foreach ($val in $expected_values){
                        if ($_.Value -match $val){
                            $match = $true
                            break
                        }
                    }
                    if ($match -eq $false){
                        $detection = [PSCustomObject]@{
                            Name = 'Non-Standard Built-In Diagnostics (BID) DLL'
                            Risk = 'High'
                            Source = 'Registry'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                Hash = Get-File-Hash $_.Value
                            }
                            Reference = "https://www.hexacorn.com/blog/2019/07/13/beyond-good-ol-run-key-part-111/"
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
}

function Check-WindowsUpdateTestDlls {
    # Can support drive retargeting
    Write-Message "Checking Windows Update Test"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Test"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -in "EventerHookDll","AllowTestEngine","AlternateServiceStackDLLPath") {
                $detection = [PSCustomObject]@{
                    Name = 'Windows Update Test DLL Exists'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
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

function Check-KnownManagedDebuggers {
    # Can support drive retargeting
    Write-Message "Checking Known Managed Debuggers"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\KnownManagedDebuggingDlls"
    $allow_list = @(
        "$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
        "$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
        "$env:homedrive\\Windows\\System32\\mrt_map\.dll"
    )
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $matches_good = $false
            foreach ($allowed_item in $allow_list){
                if ($_.Name -match $allowed_item){
                    $matches_good = $true
                    break
                }
            }
            if ($matches_good -eq $false){
                $detection = [PSCustomObject]@{
                    Name = 'Non-Standard KnownManagedDebugging DLL'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        Hash = Get-File-Hash $_.Name
                    }
                    Reference = "https://www.hexacorn.com/blog/2019/08/26/beyond-good-ol-run-key-part-113/"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-MiniDumpAuxiliaryDLLs {
    # Can support drive retargeting
    Write-Message "Checking MiniDumpAuxiliary DLLs"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
    $allow_list = @(
        "$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\coreclr\.dll"
        "$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\(mscorwks|clr)\.dll"
        "$env:homedrive\\Windows\\System32\\(chakra|jscript.*|mrt.*)\.dll"

    )
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $matches_good = $false
            foreach ($allowed_item in $allow_list){
                if ($_.Name -match $allowed_item){
                    $matches_good = $true
                    break
                }
            }
            if ($matches_good -eq $false){
                $detection = [PSCustomObject]@{
                    Name = 'Non-Standard MiniDumpAuxiliary DLL'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        Hash = Get-File-Hash $_.Name
                    }
                    Reference = "https://www.hexacorn.com/blog/2019/08/26/beyond-good-ol-run-key-part-113/"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-Wow64LayerAbuse {
    # Supports Drive Retargeting
    Write-Message "Checking WOW64 Compatibility DLLs"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Wow64\x86"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne "(Default)"){
                $detection = [PSCustomObject]@{
                    Name = 'Non-Standard Wow64\x86 DLL loaded into x86 process'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
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

function Check-EventViewerMSC {
    # Supports Drive Retargeting
    Write-Message "Checking Event Viewer MSC"
    $paths = @(
        "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer"
        "Registry::$regtarget_hklm`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Event Viewer"
    )
    foreach ($path in $paths){
        if (Test-Path -Path $path) {
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -in "MicrosoftRedirectionProgram","MicrosoftRedirectionProgramCommandLineParameters","MicrosoftRedirectionURL" -and $_.Value -notin "","http://go.microsoft.com/fwlink/events.asp"){
                    $detection = [PSCustomObject]@{
                        Name = 'Event Viewer MSC Hijack'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1574: Hijack Execution Flow"
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

function Check-SEMgrWallet {
    # Supports Drive Retargeting
    Write-Message "Checking SEMgr Wallet DLLs"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\SEMgr\Wallet"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "DllName" -and $_.Value -notin "","SEMgrSvc.dll"){
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'SEMgr'

                $detection = [PSCustomObject]@{
                    Name = 'Potential SEMgr Wallet DLL Hijack'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
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

function Check-WERRuntimeExceptionHandlers {
    # Supports Drive Retargeting
    Write-Message "Checking Error Reporting Handler DLLs"
    $allowed_entries = @(
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft\\Edge\\Application\\.*\\msedge_wer\.dll"
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\Common Files\\Microsoft Shared\\ClickToRun\\c2r64werhandler\.dll"
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\Google\\Chrome\\Application\\.*\\chrome_wer\.dll"
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE.*\\msowercrash\.dll"
        "$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Visual Studio\\.*\\Community\\common7\\ide\\VsWerHandler\.dll"
        "$env_assumedhomedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
        "$env_assumedhomedrive\\Windows\\System32\\iertutil.dll"
        "$env_assumedhomedrive\\Windows\\System32\\msiwer.dll"
        "$env_assumedhomedrive\\Windows\\System32\\wbiosrvc.dll"
        "$env_assumedhomedrive\\(Program Files|Program Files\(x86\))\\Mozilla Firefox\\mozwer.dll"
    )
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {

            $verified_match = $false
            foreach ($entry in $allowed_entries){
                #Write-Host $entry
                if ($_.Name -match $entry -and $verified_match -eq $false){
                    $verified_match = $true
                } else {
                }
            }

            if ($_.Name -ne "(Default)" -and $verified_match -eq $false){
                $detection = [PSCustomObject]@{
                    Name = 'Potential WER Helper Hijack'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1574: Hijack Execution Flow"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                    }
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-ExplorerHelperUtilities {
    # Supports Drive Retargeting
    Write-Message "Checking Explorer Helper exes"
    $paths = @(
        "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath"
        "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath"
        "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath"
    )
    $allowlisted_explorer_util_paths = @(
        "$env:SYSTEMROOT\system32\sdclt.exe"
        "$env:SYSTEMROOT\system32\cleanmgr.exe /D %c"
        "$env:SYSTEMROOT\system32\dfrgui.exe"
        "$env:SYSTEMROOT\system32\wbadmin.msc"
    )
    foreach ($path in $paths){
        if (Test-Path -Path $path) {
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq '(Default)' -and $_.Value -ne '""' -and $_.Value -notin $allowlisted_explorer_util_paths) {
                    $detection = [PSCustomObject]@{
                        Name = 'Explorer\MyComputer Utility Hijack'
                        Risk = 'Medium'
                        Source = 'Registry'
                        Technique = "T1574: Hijack Execution Flow"
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
}

function Check-TerminalServicesInitialProgram {
    # Supports Drive Retargeting
    Write-Message "Checking Terminal Services Initial Programs"
    $paths = @(
        "Registry::$regtarget_hklm`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\WinStations\RDP-Tcp"
    )
    $basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    foreach ($p in $regtarget_hkcu_list) {
        $paths += $basepath.Replace("HKEY_CURRENT_USER", $p)
    }

    foreach ($path in $paths){
        if (Test-Path -Path $path) {
            $finherit = $false
            $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq 'fInheritInitialProgram' -and $_.Value -eq "1"){
                    $finherit = $true
                }
            }
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq 'InitialProgram' -and $_.Value -ne "" -and $finherit -eq $true){
                    $detection = [PSCustomObject]@{
                        Name = 'TerminalServices InitialProgram Active'
                        Risk = 'Medium'
                        Source = 'Registry'
                        Technique = "T1574: Hijack Execution Flow"
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

function Check-RDPStartupPrograms {
    # Supports Drive Retargeting
    Write-Message "Checking RDP Startup Programs"
    $allowed_rdp_startups = @(
        "rdpclip"
    )
    $path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\Wds\rdpwd"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'StartupPrograms' -and $_.Value -ne ""){
                $packages = $_.Value.Split(",")
                foreach ($package in $packages){
                    if ($package -notin $allowed_rdp_startups){
                        $detection = [PSCustomObject]@{
                            Name = 'Non-Standard RDP Startup Program'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = [PSCustomObject]@{
                                Location = $path
                                EntryName = $_.Name
                                EntryValue = $_.Value
                                AbnormalPackage = $package
                            }
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
}

function Check-MSDTCDll {
    # TODO - Hash file - slightly difficult since it's a combination of reg paths
    # https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
    Write-Message "Checking MSDTC DLL Hijack"
    $matches = @{
        "OracleOciLib" = "oci.dll"
        "OracleOciLibPath" = "$env_assumedhomedrive\Windows\system32"
        "OracleSqlLib" = "SQLLib80.dll"
        "OracleSqlLibPath" = "$env_assumedhomedrive\Windows\system32"
        "OracleXaLib" = "xa80.dll"
        "OracleXaLibPath" = "$env_assumedhomedrive\Windows\system32"
    }
    $path = "$regtarget_hklm`SOFTWARE\Microsoft\MSDTC\MTxOCI"
    if (Test-Path -Path "Registry::$path") {
        $data = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $data.PSObject.Properties | ForEach-Object {
            if ($matches.ContainsKey($_.Name)){
                if ($_.Value -ne $matches[$_.Name]){
                    $detection = [PSCustomObject]@{
                        Name = 'MSDTC Key/Value Mismatch'
                        Risk = 'Medium'
                        Source = 'Windows MSDTC'
                        Technique = "T1574: Hijack Execution Flow"
                        Meta = [PSCustomObject]@{
                            Location = $path
                            EntryName = $_.Name
                            EntryValue = $_.Value
                            ExpectedValue = $matches[$_.Name]
                        }
                        Reference = "https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/"
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}