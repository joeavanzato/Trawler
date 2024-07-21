
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

Describe "Get-TrawlerDetectionMetrics" {
    BeforeEach {
        $detection_list = New-Object -TypeName "System.Collections.ArrayList"
        $outpath = ".\detection_test.csv"
        $output_writable = $true
    }
    Context "General Detection Metrics" {
        It "Writes 7 lines to console" {
            Get-TrawlerDetectionMetrics
            Should -Invoke -CommandName Write-Host -Times 7 -Exactly
        }
    }
    Context "General Detection Metrics" {
        It "Adds 2 detections and counts them" {
            Write-Detection $low_detection
            Get-TrawlerDetectionMetrics
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
        mock Write-TrawlerLogo
        mock Set-TrawlerPaths
        mock Invoke-DriveChange
        mock Complete-Run
        mock Get-TrawlerDetectionMetrics
        mock Search-ActiveSetup
        mock Search-AMSIProviders
        mock Search-AppCertDLLs
        mock Search-AppInitDLLs
        mock Search-ApplicationShims
        mock Search-AppPaths
        mock Search-Association-Hijack
        mock Search-AutoDialDLL
        mock Search-BIDDll
        mock Search-BITS
        mock Search-COMHijacks
        mock Search-CommandAutoRunProcessors
        mock Search-Connections
        mock Search-ContextMenu
        mock Search-DebuggerHijacks
        mock Search-DNSServerLevelPluginDLL
        mock Search-RegistryChecks
        mock Search-ErrorHandlerCMD
        mock Search-ExplorerHelperUtilities
        mock Search-FolderOpen
        mock Search-GPOExtensions
        mock Search-GPO-Scripts
        mock Search-HTMLHelpDLL
        mock Search-IFEO
        mock Search-InternetSettingsLUIDll
        mock Search-KnownManagedDebuggers
        mock Search-LNK
        mock Search-LSA
        mock Search-MicrosoftTelemetryCommands
        mock Search-ModifiedWindowsAccessibilityFeature
        mock Search-MSDTCDll
        mock Search-Narrator
        mock Search-NaturalLanguageDevelopmentDLLs
        mock Search-NetSHDLLs
        mock Search-NotepadPlusPlusPlugins
        mock Search-OfficeAI
        mock Search-OfficeGlobalDotName
        mock Search-Officetest
        mock Search-OfficeTrustedLocations
        mock Search-OutlookStartup
        mock Search-PATH-Hijacks
        mock Search-PeerDistExtensionDll
        mock Search-PolicyManager
        mock Search-PowerShellProfiles
        mock Search-PrintMonitorDLLs
        mock Search-PrintProcessorDLLs
        mock Search-Processes
        mock Search-ProcessModules
        mock Search-RATS
        mock Search-RDPShadowConsent
        mock Search-RDPStartupPrograms
        mock Search-RemoteUACSetting
        mock Search-ScheduledTasks
        mock Search-ScreenSaverEXE
        mock Search-SEMgrWallet
        mock Search-Service-Hijacks
        mock Search-Services
        mock Search-SethcHijack
        mock Search-SilentProcessExitMonitoring
        mock Search-Startups
        mock Search-Suspicious-Certificates
        mock Search-SuspiciousFileLocations
        mock Search-TerminalProfiles
        mock Search-TerminalServicesDLL
        mock Search-TerminalServicesInitialProgram
        mock Search-TimeProviderDLLs
        mock Search-TrustProviderDLL
        mock Search-UninstallStrings
        mock Search-UserInitMPRScripts
        mock Search-Users
        mock Search-UtilmanHijack
        mock Search-WellKnownCOM
        mock Search-WERRuntimeExceptionHandlers
        mock Search-WindowsLoadKey
        mock Search-Windows-Unsigned-Files
        mock Search-WindowsUpdateTestDlls
        mock Search-WinlogonHelperDLLs
        mock Search-WMIConsumers
        mock Search-Wow64LayerAbuse

        $ScanOptions = "None"
    }
    Context "Main - No Options, Default" {
        It "Should write the logo, validate provided paths, check drive-change logic, run clean-up and then finalize with detection-metrics" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Disabled, LoadSnapShot Enabled" {
        BeforeEach {
            $loadsnapshotdata = $true
            $snapshot = $false
        }
        It "Should Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 1 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Enabled, LoadSnapShot Enabled" {
        BeforeEach {
            $loadsnapshotdata = $true
            $snapshot = $true
        }
        It "Should Not Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 0 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
        }
    }
    Context "Snapshot Enabled, LoadSnapShot Disabled" {
        BeforeEach {
            $loadsnapshotdata = $false
            $snapshot = $true
        }
        It "Should Not Read-Snapshot Data from CSV" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Read-Snapshot -Times 0 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
        }
    }
    Context "Verifying Default Functionality for ScanOptions" {
        BeforeEach {
            $ScanOptions = "All"
        }
        It "Should execute all included checks" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
            Should -Invoke -CommandName Search-ActiveSetup -Times 1 -Exactly
            Should -Invoke -CommandName Search-AMSIProviders -Times 1 -Exactly
            Should -Invoke -CommandName Search-AppCertDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-AppInitDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-ApplicationShims -Times 1 -Exactly
            Should -Invoke -CommandName Search-AppPaths -Times 1 -Exactly
            Should -Invoke -CommandName Search-AssociationHijack -Times 1 -Exactly
            Should -Invoke -CommandName Search-AutoDialDLL -Times 1 -Exactly
            Should -Invoke -CommandName Search-BIDDll -Times 1 -Exactly
            Should -Invoke -CommandName Search-BITS -Times 1 -Exactly
            Should -Invoke -CommandName Search-COMHijacks -Times 1 -Exactly
            Should -Invoke -CommandName Search-CommandAutoRunProcessors -Times 1 -Exactly
            Should -Invoke -CommandName Search-Connections -Times 1 -Exactly
            Should -Invoke -CommandName Search-ContextMenu -Times 1 -Exactly
            Should -Invoke -CommandName Search-DebuggerHijacks -Times 1 -Exactly
            Should -Invoke -CommandName Search-DNSServerLevelPluginDLL -Times 1 -Exactly
            Should -Invoke -CommandName Search-RegistryChecks -Times 1 -Exactly
            Should -Invoke -CommandName Search-ErrorHandlerCMD -Times 1 -Exactly
            Should -Invoke -CommandName Search-ExplorerHelperUtilities -Times 1 -Exactly
            Should -Invoke -CommandName Search-FolderOpen -Times 1 -Exactly
            Should -Invoke -CommandName Search-GPOExtensions -Times 1 -Exactly
            Should -Invoke -CommandName Search-GPO-Scripts -Times 1 -Exactly
            Should -Invoke -CommandName Search-HTMLHelpDLL -Times 1 -Exactly
            Should -Invoke -CommandName Search-IFEO -Times 1 -Exactly
            Should -Invoke -CommandName Search-InternetSettingsLUIDll -Times 1 -Exactly
            Should -Invoke -CommandName Search-KnownManagedDebuggers -Times 1 -Exactly
            Should -Invoke -CommandName Search-LNK -Times 1 -Exactly
            Should -Invoke -CommandName Search-LSA -Times 1 -Exactly
            Should -Invoke -CommandName Search-MicrosoftTelemetryCommands -Times 1 -Exactly
            Should -Invoke -CommandName Search-ModifiedWindowsAccessibilityFeature -Times 1 -Exactly
            Should -Invoke -CommandName Search-MSDTCDll -Times 1 -Exactly
            Should -Invoke -CommandName Search-Narrator -Times 1 -Exactly
            Should -Invoke -CommandName Search-NaturalLanguageDevelopmentDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-NetSHDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-NotepadPlusPlusPlugins -Times 1 -Exactly
            Should -Invoke -CommandName Search-OfficeAI -Times 1 -Exactly
            Should -Invoke -CommandName Search-OfficeGlobalDotName -Times 1 -Exactly
            Should -Invoke -CommandName Search-Officetest -Times 1 -Exactly
            Should -Invoke -CommandName Search-OfficeTrustedLocations -Times 1 -Exactly
            Should -Invoke -CommandName Search-OutlookStartup -Times 1 -Exactly
            Should -Invoke -CommandName Search-PATH-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Search-PeerDistExtensionDll -Times 1 -Exactly
            Should -Invoke -CommandName Search-PolicyManager -Times 1 -Exactly
            Should -Invoke -CommandName Search-PowerShellProfiles -Times 1 -Exactly
            Should -Invoke -CommandName Search-PrintMonitorDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-PrintProcessorDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-Processes -Times 1 -Exactly
            Should -Invoke -CommandName Search-ProcessModules -Times 1 -Exactly
            Should -Invoke -CommandName Search-RATS -Times 1 -Exactly
            Should -Invoke -CommandName Search-RDPShadowConsent -Times 1 -Exactly
            Should -Invoke -CommandName Search-RDPStartupPrograms -Times 1 -Exactly
            Should -Invoke -CommandName Search-RemoteUACSetting -Times 1 -Exactly
            Should -Invoke -CommandName Search-ScheduledTasks -Times 1 -Exactly
            Should -Invoke -CommandName Search-ScreenSaverEXE -Times 1 -Exactly
            Should -Invoke -CommandName Search-SEMgrWallet -Times 1 -Exactly
            Should -Invoke -CommandName Search-Service-Hijacks -Times 1 -Exactly
            Should -Invoke -CommandName Search-Services -Times 1 -Exactly
            Should -Invoke -CommandName Search-SethcHijack -Times 1 -Exactly
            Should -Invoke -CommandName Search-SilentProcessExitMonitoring -Times 1 -Exactly
            Should -Invoke -CommandName Search-Startups -Times 1 -Exactly
            Should -Invoke -CommandName Search-Suspicious-Certificates -Times 1 -Exactly
            Should -Invoke -CommandName Search-SuspiciousFileLocations -Times 1 -Exactly
            Should -Invoke -CommandName Search-TerminalProfiles -Times 1 -Exactly
            Should -Invoke -CommandName Search-TerminalServicesDLL -Times 1 -Exactly
            Should -Invoke -CommandName Search-TerminalServicesInitialProgram -Times 1 -Exactly
            Should -Invoke -CommandName Search-TimeProviderDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-TrustProviderDLL -Times 1 -Exactly
            Should -Invoke -CommandName Search-UninstallStrings -Times 1 -Exactly
            Should -Invoke -CommandName Search-UserInitMPRScripts -Times 1 -Exactly
            Should -Invoke -CommandName Search-Users -Times 1 -Exactly
            Should -Invoke -CommandName Search-UtilmanHijack -Times 1 -Exactly
            Should -Invoke -CommandName Search-WellKnownCOM -Times 1 -Exactly
            Should -Invoke -CommandName Search-WERRuntimeExceptionHandlers -Times 1 -Exactly
            Should -Invoke -CommandName Search-WindowsLoadKey -Times 1 -Exactly
            Should -Invoke -CommandName Search-Windows-Unsigned-Files -Times 1 -Exactly
            Should -Invoke -CommandName Search-WindowsUpdateTestDlls -Times 1 -Exactly
            Should -Invoke -CommandName Search-WinlogonHelperDLLs -Times 1 -Exactly
            Should -Invoke -CommandName Search-WMIConsumers -Times 1 -Exactly
            Should -Invoke -CommandName Search-Wow64LayerAbuse -Times 1 -Exactly
        }
    }
    Context "Verifying Scan Options Functionality" {
        BeforeEach {
            $ScanOptions = "ActiveSetup", "AMSIProviders"
        }
        It "Should only execute Search-ActiveSetup and CheckAMSIProviders" {
            Main
            Should -Invoke -CommandName Write-TrawlerLogo -Times 1 -Exactly
            Should -Invoke -CommandName Set-TrawlerPaths -Times 1 -Exactly
            Should -Invoke -CommandName Invoke-DriveChange -Times 1 -Exactly
            Should -Invoke -CommandName Complete-Run -Times 1 -Exactly
            Should -Invoke -CommandName Get-TrawlerDetectionMetrics -Times 1 -Exactly
            Should -Invoke -CommandName Search-ActiveSetup -Times 1 -Exactly
            Should -Invoke -CommandName Search-AMSIProviders -Times 1 -Exactly
            Should -Invoke -CommandName Search-AppInitDLLs -Times 0 -Exactly
        }
    }
}

Describe "Logo" {
    Context "Writing Write-TrawlerLogo to Console" {
        It "Should Write 4 lines to the console" {
             Write-TrawlerLogo 
            Should -Invoke -CommandName Write-Host -Times 4 -Exactly
        }
    }
}

Describe "Complete-Run" {
    Context "Checking Complete-Run Script with no drive change" {
        BeforeEach {
            $drivechange = $false
            $new_psdrives_list = @()
            mock Unpublish-Hive
        }
        It "Should Do Nothing" {
            Complete-Run
            Should -Invoke -CommandName Unpublish-Hive -Times 0 -Exactly
        }
    }
    Context "Checking Complete-Run Script with no drive change" {
        BeforeEach {
            $drivechange = $true
            $new_psdrives_list = @("TEST1", "TEST2")
            mock Unpublish-Hive
        }
            It "Should Attempt to Unload Each Drive present in new_psdrives_list" {
            Complete-Run
            Should -Invoke -CommandName Unpublish-Hive -Times 2 -Exactly
        }
    }
}

Describe "Invoke-DriveChange" {
    Context "Drive ReTargeting Disabled" {
        BeforeEach {
            $drivechange = $false
            mock Get-ChildItem
        }
        It "Should Execute Get-ChildItem Once" {
            Invoke-DriveChange
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
        # Can't fully test because using 'exit' - need to refactor Invoke-DriveChange to avoid exit in a cleaner way
        BeforeEach {
            $drivechange = $true
            mock Publish-Hive
            $drivetarget = "C:"
        }
        #It "Should Execute Publish-Hive" {
        #    Invoke-DriveChange
        #    Should -Invoke -CommandName Publish-Hive -BeGreaterThan 1
        #}
        #It "Should create script level variables for various configurations" {
        #    Invoke-DriveChange
        #    $script:env_homedrive = $drivetarget
        #    $script:env_assumedhomedrive = 'C:'
        #    $script:env_programdata = $drivetarget + "\ProgramData"
        #}
    }
}

Describe "Search-SuspiciousFileLocations" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 3 detections for suspicious exe files" {
        $testPath = New-Item "$env_homedrive\Users\Public\test.exe" -ItemType File -Force
        $testPath2 = New-Item "$env_homedrive\Users\Administrator\test.exe" -ItemType File -Force
        $testPath3 = New-Item "$env_homedrive\Users\Public\hello\test.exe" -ItemType File -Force
        Search-SuspiciousFileLocations
        Should -Invoke -CommandName Write-Detection -Times 3 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        Remove-Item $testPath2 -Force -ErrorAction SilentlyContinue
        Remove-Item $testPath3 -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections for suspicious exe files" {
        Search-SuspiciousFileLocations
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Search-Narrator" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detection" {
        $testPath = New-Item "$env_homedrive\Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL" -ItemType File -Force
        Search-Narrator
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        Search-Narrator
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Search-MSDTCDll" {
    BeforeEach {
        $path = "TestRegistry:\SOFTWARE\Microsoft\MSDTC"
        New-Item $path -Name "MTxOCI" -Force
        New-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLib" -Value "oci.dll"
        Mock Write-Detection
    }
    It "should write 0 detections" {
        Search-MSDTCDll
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 6 detection" {
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleOciLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleSqlLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleSqlLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleXaLib" -Value "test.dll"
        Set-ItemProperty  -Path "$path\MTxOCI" -Name "OracleXaLibPath" -Value "$env_assumedhomedrive\Users\Public\test.dll"
        Search-MSDTCDll
        Should -Invoke -CommandName Write-Detection -Times 6 -Exactly
    }
}

Describe "Search-NotepadPlusPlusPlugins" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detections" {
        $testPath = New-Item "$env_homedrive\Program Files\Notepad++\plugins\test\test.dll" -ItemType File -Force
        Search-NotepadPlusPlusPlugins
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        New-Item "$env_homedrive\Program Files\Notepad++\plugins\Config\nppPluginList.dll" -ItemType File -Force
        Search-NotepadPlusPlusPlugins
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Search-OfficeAI" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
    }
    It "should write 1 detections" {
        $testPath = New-Item "$env_homedrive\Program Files\Microsoft Office\root\Office16\ai.exe" -ItemType File -Force
        Search-OfficeAI
        Should -Invoke -CommandName Write-Detection -Times 1 -Exactly
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
    }
    It "should write 0 detections" {
        Search-OfficeAI
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
}

Describe "Search-ContextMenu" {
    BeforeEach {
        $path = "TestRegistry:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
        New-Item -Path "$path\Test" -Force
        New-ItemProperty  -Path "$path\Test" -Name "(Default)" -Value "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}"
        Mock Write-Detection
    }
    It "should write 0 detections" {
        Search-ContextMenu
        Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 2 detections" {
        Set-ItemProperty  -Path "$path\Test" -Name "(Default)" -Value "test.dll"
        Search-ContextMenu
        Should -Invoke -CommandName Write-Detection -Times 2 -Exactly
    }
}

Describe "Search-RATS" {
    BeforeEach {
        $env_homedrive = "TestDrive:"
        Mock Write-Detection
        New-Item "$env_homedrive\Users\test_user" -ItemType File -Force
    }
    It "should write 0 detections" {
        #Search-RATS
        #Should -Invoke -CommandName Write-Detection -Times 0 -Exactly
    }
    It "should write 3 detections" {
        New-Item "$env_programdata\AMMYY\access.log" -ItemType File -Force
        New-Item "$env_homedrive\Windows\dwrcs" -ItemType Directory -Force
        New-Item "$env_homedrive\Users\test_user\AppData\Local\GoTo" -ItemType Directory -Force
        #Search-RATS
        #Should -Invoke -CommandName Write-Detection -Times 6 -Exactly
    }
}
