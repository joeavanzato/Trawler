
# Invoke-Pester -CodeCoverage  .\trawler.ps1
# Invoke-Pester

BeforeAll {
    . .\trawler.ps1
    $detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'Medium'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    $low_detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'Low'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    $high_detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'High'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    mock Export-CSV
    mock Write-Host
    $outpath = ".\detection_test.csv"
    $snapshotpath = ".\snapshot_test.csv"
    $regtarget_hklm = (Get-PSDrive TestRegistry).Root+"\"
    $regtarget_hkcu_list = @($regtarget_hklm)
    $env_assumedhomedrive = "C:"
    $env_homedrive = "TestDrive:"
    $env_programdata = "C:\ProgramData"
}

Describe "Write-Detection" {
    BeforeEach {
        $detection_list = New-Object -TypeName "System.Collections.ArrayList"
    }
    Context "Console not suppressed" {
        BeforeAll {
            $hide_console_output = $false
        }
        It "Writes two lines to console" {
            Write-Detection $detection
            Should -Invoke -CommandName Write-Host -Times 2 -Exactly
        }
    }
    Context "Console suppressed" {
        BeforeAll {
            $hide_console_output = $true
        }
        It "Writes zero lines to console" {
            Write-Detection $detection
            Should -Invoke -CommandName Write-Host -Times 0 -Exactly
        }
    }
    Context "Output File is Writable" {
        BeforeAll {
            $output_writable = $true
        }
        It "Should output to file" {
            Write-Detection $detection
            Should -Invoke -CommandName Export-CSV -Times 1 -Exactly
        }
    }
    Context "Output File is not Writable" {
        BeforeAll {
            $output_writable = $false
        }
        It "Should not output to file" {
            Write-Detection $detection
            Should -Invoke -CommandName Export-CSV -Times 0 -Exactly
        }
    }
    Context "Detection Added to List" {
        It "Should add one detection to detection_list" {
            Write-Detection $detection
            $detection_list.Count | Should -Be 1
        }
    }
}

Describe "Detection-Metrics" {
    BeforeEach {
        $detection_list = New-Object -TypeName "System.Collections.ArrayList"
        $outpath = ".\detection_test.csv"
        $output_writable = $true
    }
    Context "General Detection Metrics" {
        It "Writes 7 lines to console" {
            Detection-Metrics
            Should -Invoke -CommandName Write-Host -Times 7 -Exactly
        }
    }
    Context "General Detection Metrics" {
        It "Adds 2 detections and counts them" {
            Write-Detection $low_detection
            Detection-Metrics
            Should -Invoke -CommandName Export-CSV -Times 1 -Exactly
            $detection_list.Count | Should -Be 1
        }
    }
}

Describe "Write-Message" {
    Context "Write Message" {
        It "Writes 1 line to console" {
            Write-Message
            Should -Invoke -CommandName Write-Host -Times 1 -Exactly
        }
    }
}

Describe "Write-SnapshotMessage" {
    BeforeEach {
        $script:snapshotpath_writable = $true
        $snapshot = $true
        $key = "KeyTest"
        $value = "ValueTest"
        $source = "SourceTest"
    }
    Context "Snapshot Enabled and Path Writeable" {

        It "Writes Message to CSV" {
            Write-SnapshotMessage -Key $key -Value $value -Source $source
            Should -Invoke -CommandName Export-CSV -Times 1 -Exactly
        }
    }
    Context "Snapshot Disabled and Path Writeable" {
        BeforeEach {
            $snapshot = $false
        }
        It "Returns without writing message to CSV" {
            Write-SnapshotMessage -Key $key -Value $value -Source $source
            Should -Invoke -CommandName Export-CSV -Times 0 -Exactly
        }
    }
    Context "Snapshot Enabled and Path Not-Writeable" {
        BeforeEach {
            $script:snapshotpath_writable = $false
        }
        It "Returns without writing message to CSV" {
            Write-SnapshotMessage -Key $key -Value $value -Source $source
            Should -Invoke -CommandName Export-CSV -Times 0 -Exactly
        }
    }
    Context "Snapshot Disabled and Path Not-Writeable" {
        BeforeEach {
            $snapshot = $false
            $script:snapshotpath_writable = $false
        }
        It "Returns without writing message to CSV" {
            Write-SnapshotMessage -Key $key -Value $value -Source $source
            Should -Invoke -CommandName Export-CSV -Times 0 -Exactly
        }
    }
}

Describe "Main" {
    BeforeAll {
        mock Read-Snapshot
        mock Logo
        mock ValidatePaths
        mock Drive-Change
        mock Clean-Up
        mock Detection-Metrics
        mock Check-ActiveSetup
        mock Check-AMSIProviders
        mock Check-AppCertDLLs
        mock Check-AppInitDLLs
        mock Check-ApplicationShims
        mock Check-AppPaths
        mock Check-Association-Hijack
        mock Check-AutoDialDLL
        mock Check-BIDDll
        mock Check-BITS
        mock Check-COM-Hijacks
        mock Check-CommandAutoRunProcessors
        mock Check-Connections
        mock Check-ContextMenu
        mock Check-Debugger-Hijacks
        mock Check-DNSServerLevelPluginDLL
        mock Check-Registry-Checks
        mock Check-ErrorHandlerCMD
        mock Check-ExplorerHelperUtilities
        mock Check-FolderOpen
        mock Check-GPOExtensions
        mock Check-GPO-Scripts
        mock Check-HTMLHelpDLL
        mock Check-IFEO
        mock Check-InternetSettingsLUIDll
        mock Check-KnownManagedDebuggers
        mock Check-LNK
        mock Check-LSA
        mock Check-MicrosoftTelemetryCommands
        mock Check-Modified-Windows-Accessibility-Feature
        mock Check-MSDTCDll
        mock Check-Narrator
        mock Check-NaturalLanguageDevelopmentDLLs
        mock Check-NetSHDLLs
        mock Check-Notepad++-Plugins
        mock Check-OfficeAI
        mock Check-OfficeGlobalDotName
        mock Check-Officetest
        mock Check-Office-Trusted-Locations
        mock Check-Outlook-Startup
        mock Check-PATH-Hijacks
        mock Check-PeerDistExtensionDll
        mock Check-PolicyManager
        mock Check-PowerShell-Profiles
        mock Check-PrintMonitorDLLs
        mock Check-PrintProcessorDLLs
        mock Check-Processes
        mock Check-Process-Modules
        mock Check-RATS
        mock Check-RDPShadowConsent
        mock Check-RDPStartupPrograms
        mock Check-RemoteUACSetting
        mock Check-ScheduledTasks
        mock Check-ScreenSaverEXE
        mock Check-SEMgrWallet
        mock Check-Service-Hijacks
        mock Check-Services
        mock Check-SethcHijack
        mock Check-SilentProcessExitMonitoring
        mock Check-Startups
        mock Check-Suspicious-Certificates
        mock Check-Suspicious-File-Locations
        mock Check-TerminalProfiles
        mock Check-TerminalServicesDLL
        mock Check-TerminalServicesInitialProgram
        mock Check-TimeProviderDLLs
        mock Check-TrustProviderDLL
        mock Check-UninstallStrings
        mock Check-UserInitMPRScripts
        mock Check-Users
        mock Check-UtilmanHijack
        mock Check-WellKnownCOM
        mock Check-WERRuntimeExceptionHandlers
        mock Check-WindowsLoadKey
        mock Check-Windows-Unsigned-Files
        mock Check-WindowsUpdateTestDlls
        mock Check-WinlogonHelperDLLs
        mock Check-WMIConsumers
        mock Check-Wow64LayerAbuse

        $ScanOptions = "None"
    }
    Context "Main - No Options, Default" {
        It "Should write the logo, validate provided paths, check drive-change logic, run clean-up and then finalize with detection-metrics" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Disabled, LoadSnapShot Enabled" {
        BeforeEach {
            $loadsnapshotdata = $true
            $snapshot = $false
        }
        It "Should Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 1 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Enabled, LoadSnapShot Enabled" {
        BeforeEach {
            $loadsnapshotdata = $true
            $snapshot = $true
        }
        It "Should Not Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 0 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Enabled, LoadSnapShot Disabled" {
        BeforeEach {
            $loadsnapshotdata = $false
            $snapshot = $true
        }
        It "Should Not Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 0 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
        }
    }
    Context "Verifying Default Functionality for ScanOptions" {
        BeforeEach {
            $ScanOptions = "All"
        }
        It "Should execute all included checks" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
            Should -Invoke -CommandName Check-ActiveSetup -Times 1 -Exactly
            Should -Invoke -CommandName Check-AMSIProviders -Times 1 -Exactly
            Should -Invoke -CommandName Check-AppCertDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-AppInitDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-ApplicationShims -Times 1 -Exactly
            Should -Invoke -CommandName Check-AppPaths -Times 1 -Exactly
            Should -Invoke -CommandName Check-Association-Hijack -Times 1 -Exactly
            Should -Invoke -CommandName Check-AutoDialDLL -Times 1 -Exactly
            Should -Invoke -CommandName Check-BIDDll -Times 1 -Exactly
            Should -Invoke -CommandName Check-BITS -Times 1 -Exactly
            Should -Invoke -CommandName Check-COM-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Check-CommandAutoRunProcessors -Times 1 -Exactly
            Should -Invoke -CommandName Check-Connections -Times 1 -Exactly
            Should -Invoke -CommandName Check-ContextMenu -Times 1 -Exactly
            Should -Invoke -CommandName Check-Debugger-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Check-DNSServerLevelPluginDLL -Times 1 -Exactly
            Should -Invoke -CommandName Check-Registry-Checks -Times 1 -Exactly
            Should -Invoke -CommandName Check-ErrorHandlerCMD -Times 1 -Exactly
            Should -Invoke -CommandName Check-ExplorerHelperUtilities -Times 1 -Exactly
            Should -Invoke -CommandName Check-FolderOpen -Times 1 -Exactly
            Should -Invoke -CommandName Check-GPOExtensions -Times 1 -Exactly
            Should -Invoke -CommandName Check-GPO-Scripts -Times 1 -Exactly
            Should -Invoke -CommandName Check-HTMLHelpDLL -Times 1 -Exactly
            Should -Invoke -CommandName Check-IFEO -Times 1 -Exactly
            Should -Invoke -CommandName Check-InternetSettingsLUIDll -Times 1 -Exactly
            Should -Invoke -CommandName Check-KnownManagedDebuggers -Times 1 -Exactly
            Should -Invoke -CommandName Check-LNK -Times 1 -Exactly
            Should -Invoke -CommandName Check-LSA -Times 1 -Exactly
            Should -Invoke -CommandName Check-MicrosoftTelemetryCommands -Times 1 -Exactly
            Should -Invoke -CommandName Check-Modified-Windows-Accessibility-Feature -Times 1 -Exactly
            Should -Invoke -CommandName Check-MSDTCDll -Times 1 -Exactly
            Should -Invoke -CommandName Check-Narrator -Times 1 -Exactly
            Should -Invoke -CommandName Check-NaturalLanguageDevelopmentDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-NetSHDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-Notepad++-Plugins -Times 1 -Exactly
            Should -Invoke -CommandName Check-OfficeAI -Times 1 -Exactly
            Should -Invoke -CommandName Check-OfficeGlobalDotName -Times 1 -Exactly
            Should -Invoke -CommandName Check-Officetest -Times 1 -Exactly
            Should -Invoke -CommandName Check-Office-Trusted-Locations -Times 1 -Exactly
            Should -Invoke -CommandName Check-Outlook-Startup -Times 1 -Exactly
            Should -Invoke -CommandName Check-PATH-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Check-PeerDistExtensionDll -Times 1 -Exactly
            Should -Invoke -CommandName Check-PolicyManager -Times 1 -Exactly
            Should -Invoke -CommandName Check-PowerShell-Profiles -Times 1 -Exactly
            Should -Invoke -CommandName Check-PrintMonitorDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-PrintProcessorDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-Processes -Times 1 -Exactly
            Should -Invoke -CommandName Check-Process-Modules -Times 1 -Exactly
            Should -Invoke -CommandName Check-RATS -Times 1 -Exactly
            Should -Invoke -CommandName Check-RDPShadowConsent -Times 1 -Exactly
            Should -Invoke -CommandName Check-RDPStartupPrograms -Times 1 -Exactly
            Should -Invoke -CommandName Check-RemoteUACSetting -Times 1 -Exactly
            Should -Invoke -CommandName Check-ScheduledTasks -Times 1 -Exactly
            Should -Invoke -CommandName Check-ScreenSaverEXE -Times 1 -Exactly
            Should -Invoke -CommandName Check-SEMgrWallet -Times 1 -Exactly
            Should -Invoke -CommandName Check-Service-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Check-Services -Times 1 -Exactly
            Should -Invoke -CommandName Check-SethcHijack -Times 1 -Exactly
            Should -Invoke -CommandName Check-SilentProcessExitMonitoring -Times 1 -Exactly
            Should -Invoke -CommandName Check-Startups -Times 1 -Exactly
            Should -Invoke -CommandName Check-Suspicious-Certificates -Times 1 -Exactly
            Should -Invoke -CommandName Check-Suspicious-File-Locations -Times 1 -Exactly
            Should -Invoke -CommandName Check-TerminalProfiles -Times 1 -Exactly
            Should -Invoke -CommandName Check-TerminalServicesDLL -Times 1 -Exactly
            Should -Invoke -CommandName Check-TerminalServicesInitialProgram -Times 1 -Exactly
            Should -Invoke -CommandName Check-TimeProviderDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-TrustProviderDLL -Times 1 -Exactly
            Should -Invoke -CommandName Check-UninstallStrings -Times 1 -Exactly
            Should -Invoke -CommandName Check-UserInitMPRScripts -Times 1 -Exactly
            Should -Invoke -CommandName Check-Users -Times 1 -Exactly
            Should -Invoke -CommandName Check-UtilmanHijack -Times 1 -Exactly
            Should -Invoke -CommandName Check-WellKnownCOM -Times 1 -Exactly
            Should -Invoke -CommandName Check-WERRuntimeExceptionHandlers -Times 1 -Exactly
            Should -Invoke -CommandName Check-WindowsLoadKey -Times 1 -Exactly
            Should -Invoke -CommandName Check-Windows-Unsigned-Files -Times 1 -Exactly
            Should -Invoke -CommandName Check-WindowsUpdateTestDlls -Times 1 -Exactly
            Should -Invoke -CommandName Check-WinlogonHelperDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Check-WMIConsumers -Times 1 -Exactly
            Should -Invoke -CommandName Check-Wow64LayerAbuse -Times 1 -Exactly
        }
    }
    Context "Verifying Scan Options Functionality" {
        BeforeEach {
            $ScanOptions = "ActiveSetup", "AMSIProviders"
        }
        It "Should only execute Check-ActiveSetup and CheckAMSIProviders" {
            Main
            Should -Invoke -CommandName Logo -Times 1 -Exactly
            Should -Invoke -CommandName ValidatePaths -Times 1 -Exactly
            Should -Invoke -CommandName Drive-Change -Times 1 -Exactly
            Should -Invoke -CommandName Clean-Up -Times 1 -Exactly
            Should -Invoke -CommandName Detection-Metrics -Times 1 -Exactly
            Should -Invoke -CommandName Check-ActiveSetup -Times 1 -Exactly
            Should -Invoke -CommandName Check-AMSIProviders -Times 1 -Exactly
            Should -Invoke -CommandName Check-AppInitDLLs -Times 0 -Exactly
        }
    }
}

Describe "Logo" {
    Context "Writing Logo to Console" {
        It "Should Write 4 lines to the console" {
            Logo
            Should -Invoke -CommandName Write-Host -Times 4 -Exactly
        }
    }
}

Describe "Clean-Up" {
    Context "Checking Clean-Up Script with no drive change" {
        BeforeEach {
            $drivechange = $false
            $new_psdrives_list = @()
            mock Unload-Hive
        }
        It "Should Do Nothing" {
            Clean-Up
            Should -Invoke -CommandName Unload-Hive -Times 0 -Exactly
        }
    }
    Context "Checking Clean-Up Script with no drive change" {
        BeforeEach {
            $drivechange = $true
            $new_psdrives_list = @("TEST1", "TEST2")
            mock Unload-Hive
        }
            It "Should Attempt to Unload Each Drive present in new_psdrives_list" {
            Clean-Up
            Should -Invoke -CommandName Unload-Hive -Times 2 -Exactly
        }
    }
}

Describe "Drive-Change" {
    Context "Drive ReTargeting Disabled" {
        BeforeEach {
            $drivechange = $false
            mock Get-ChildItem
        }
        It "Should Execute Get-ChildItem Once" {
            Drive-Change
            Should -Invoke -CommandName Get-ChildItem -Times 1 -Exactly
        }
        It "Should create script level variables for various configurations" {
          $script:env_homedrive | Should -Be $env:homedrive
          $script:env_assumedhomedrive | Should -Be $env:homedrive
          $script:env_programdata | Should -Be $env:programdata
          $script:regtarget_hklm | Should -Be "HKEY_LOCAL_MACHINE\"
          $script:regtarget_hkcu | Should -Be "HKEY_CURRENT_USER\"
          $script:regtarget_hkcr | Should -Be "HKEY_CLASSES_ROOT\"
          $script:currentcontrolset | Should -Be "CurrentControlSet"
        }
    }
    Context "Drive ReTargeting Enabled" {
        # Can't fully test because using 'exit' - need to refactor Drive-Change to avoid exit in a cleaner way
        BeforeEach {
            $drivechange = $true
            mock Load-Hive
            $drivetarget = "C:"
        }
        #It "Should Execute Load-Hive" {
        #    Drive-Change
        #    Should -Invoke -CommandName Load-Hive -BeGreaterThan 1
        #}
        #It "Should create script level variables for various configurations" {
        #    Drive-Change
        #    $script:env_homedrive = $drivetarget
        #    $script:env_assumedhomedrive = 'C:'
        #    $script:env_programdata = $drivetarget + "\ProgramData"
        #}
    }
}

Describe "Check-Suspicious-File-Locations" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 3 detections for suspicious exe files" {
        $testPath = New-Item "$env_homedrive\Users\Public\test.exe" -ItemType File -Force
        $testPath2 = New-Item "$env_homedrive\Users\Administrator\test.exe" -ItemType File -Force
        $testPath3 = New-Item "$env_homedrive\Users\Public\hello\test.exe" -ItemType File -Force
        Check-Suspicious-File-Locations
        Should -Invoke -CommandName Write-Detection -Times 3 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        Remove-Item $testPath2 -Force -ErrorAction SilentlyContinue
        Remove-Item $testPath3 -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections for suspicious exe files" {
        Check-Suspicious-File-Locations
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Check-Narrator" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detection" {
        $testPath = New-Item "$env_homedrive\Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL" -ItemType File -Force
        Check-Narrator
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        Check-Narrator
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Check-MSDTCDll" {
    BeforeEach {
        $path = "TestRegistry:\SOFTWARE\Microsoft\MSDTC"
        New-Item $path -Name "MTxOCI" -Force
        New-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLib" -Value "oci.dll"
        Mock Write-Detection
    }
    It "should write 0 detections" {
        Check-MSDTCDll
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 6 detection" {
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleSqlLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleSqlLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleXaLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleXaLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Check-MSDTCDll
        Should -Invoke -CommandName Write-Detection -Times 6 -Exactly
    }
}

Describe "Check-Notepad++-Plugins" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detections" {
        $testPath = New-Item "$env_homedrive\Program Files\Notepad++\plugins\test\test.dll" -ItemType File -Force
        Check-Notepad++-Plugins
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        New-Item "$env_homedrive\Program Files\Notepad++\plugins\Config\nppPluginList.dll" -ItemType File -Force
        Check-Notepad++-Plugins
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Check-OfficeAI" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detections" {
        $testPath = New-Item "$env_homedrive\Program Files\Microsoft Office\root\Office16\ai.exe" -ItemType File -Force
        Check-OfficeAI
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        Check-OfficeAI
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Check-ContextMenu" {
    BeforeEach {
        $path = "TestRegistry:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
        New-Item -Path "$path\Test" -Force
        New-ItemProperty  -Path "$path\Test" -Name "(Default)" -Value "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}"
        Mock Write-Detection
    }
    It "should write 0 detections" {
        Check-ContextMenu
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 2 detections" {
        Set-ItemProperty  -Path "$path\Test" -Name "(Default)" -Value "test.dll"
        Check-ContextMenu
        Should -Invoke -CommandName Write-Detection -Times 2 -Exactly
    }
}

Describe "Check-RATS" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
        New-Item "$env_homedrive\Users\test_user" -ItemType File -Force
    }
    It "should write 0 detections" {
        #Check-RATS
        #Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 3 detections" {
        New-Item "$env_programdata\AMMYY\access.log" -ItemType File -Force
        New-Item "$env_homedrive\Windows\dwrcs" -ItemType Directory -Force
        New-Item "$env_homedrive\Users\test_user\AppData\Local\GoTo" -ItemType Directory -Force
        #Check-RATS
        #Should -Invoke -CommandName Write-Detection -Times 6 -Exactly
    }
}
