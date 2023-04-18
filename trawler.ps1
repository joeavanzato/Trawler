<#
	.SYNOPSIS
		trawler is designed to help Incident Responders discover suspicious persistence mechanisms on Windows devices.
	
	.DESCRIPTION
		trawler inspects a constantly-growing variety of Windows artifacts to help discover signals of persistence including the registry, scheduled tasks, services, startup items, etc.
	
	.PARAMETER outpath
		The fully-qualified file-path where detection output should be stored as a CSV.
	
	.PARAMETER outputPath
		A description of the outputPath parameter.
	
	.EXAMPLE
		.\trawler.ps1
		.\trawler.ps1 -outpath "C:\detections.csv"
	
	.OUTPUTS
		None
	
	.NOTES
		None
	
	.INPUTS
		None
	
	.LINK
		https://github.com/joeavanzato/Trawler
#>
param
(
	[Parameter(Mandatory = $false,
			   Position = 1,
			   HelpMessage = 'Please provide the fully-qualified file-path where detection output should be stored as a CSV.')]
	[string]$outpath = "$PSScriptRoot\detections.csv"
)

function Get-ValidOutPath
{
	param (
		[string]$path
	)

	while (Test-Path -Path $path -PathType Container)
	{
		Write-Warning "The provided path is a folder, not a file. Please provide a file path."
		$path = Read-Host "Enter a valid file path"
	}

	return $path
}

# TODO - Rearrange this functionality inside of Get-ValidOutPath if we want to halt execution prior to having a viable write path - unsure still.
Try {
    $outpath = Get-ValidOutPath -path $outpath
    Write-Host "Using the following file path: $outpath"
    [io.file]::OpenWrite($outpath).close()
    $output_writable = $true
}
Catch {
    Write-Warning "Unable to write to provided output path: $outpath"
    $output_writable = $false
}

# TODO - JSON Output for more detail
# TODO - Non-Standard Service/Task running as/created by Local Administrator
# TODO - Scanning Microsoft Office Trusted Locations for non-standard templates/add-ins
# TODO - Scanning File Extension Associations for potential threats
# TODO - Browser Extension Analysis
# TODO - Installed Certificate Scanning
# TODO - Temporary RID Hijacking
# TODO - ntshrui.dll - https://www.mandiant.com/resources/blog/malware-persistence-windows-registry
# TODO - Add file metadata for detected files (COM Hijacks, etc)

# TODO - Add more suspicious paths for running processes
$suspicious_process_paths = @(
	".*\\users\\administrator\\.*",
	".*\\users\\default\\.*",
	".*\\users\\public\\.*",
	".*\\windows\\debug\\.*",
	".*\\windows\\fonts\\.*",
	".*\\windows\\media\\.*",
	".*\\windows\\repair\\.*",
	".*\\windows\\servicing\\.*",
	".*\\windows\\temp\\.*",
	".*recycle.bin.*"
)
$ipv4_pattern = '.*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*'
$ipv6_pattern = '.*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*'


function Scheduled-Tasks {
    $tasks = Get-ScheduledTask  | Select-Object -Property State,Actions,Author,Date,Description,Principal,SecurityDescriptor,Settings,TaskName,TaskPath,Triggers,URI, @{Name="RunAs";Expression={ $_.principal.userid }} -ExpandProperty Actions | Select-Object *

    $default_task_exe_paths = @(
		'"%ProgramFiles%\Windows Media Player\wmpnscfg.exe"',
		"%SystemRoot%\System32\ClipRenew.exe",
		"%SystemRoot%\System32\ClipUp.exe",
		"%SystemRoot%\System32\drvinst.exe",
		"%SystemRoot%\System32\dsregcmd.exe",
		"%SystemRoot%\System32\dusmtask.exe",
		"%SystemRoot%\System32\fclip.exe",
		"%SystemRoot%\System32\MbaeParserTask.exe",
		"%systemroot%\System32\MusNotification.exe",
		"%systemroot%\System32\sihclient.exe",
		"%systemroot%\System32\usoclient.exe",
		"%SystemRoot%\System32\WiFiTask.exe",
		"%SystemRoot%\System32\wsqmcons.exe",
		"%windir%\System32\AppHostRegistrationVerifier.exe",
		"%windir%\System32\appidcertstorecheck.exe",
		"%windir%\System32\appidcertstorecheck.exe".
		"%windir%\System32\appidpolicyconverter.exe",
		"%windir%\System32\bcdboot.exe",
		"%windir%\System32\cleanmgr.exe",
		"%windir%\System32\compattelrunner.exe",
		"%windir%\System32\defrag.exe",
		"%windir%\System32\devicecensus.exe",
		"%windir%\System32\DFDWiz.exe",
		"%windir%\System32\directxdatabaseupdater.exe",
		"%windir%\System32\disksnapshot.exe",
		"%windir%\System32\dmclient.exe",
		"%windir%\System32\dstokenclean.exe",
		"%windir%\System32\dxgiadaptercache.exe",
		"%windir%\System32\eduprintprov.exe",
		"%windir%\System32\gatherNetworkInfo.vbs",
		"%windir%\System32\LocationNotificationWindows.exe",
		"%windir%\System32\lpremove.exe",
		"%windir%\System32\ProvTool.exe",
		"%windir%\System32\RAServer.exe",
		"%windir%\System32\rundll32.exe",
		"%windir%\System32\sc.exe",
		"%windir%\System32\SDNDiagnosticsTask.exe",
		"%WINDIR%\System32\SecureBootEncodeUEFI.exe",
		"%windir%\System32\ServerManagerLauncher.exe",
		"%windir%\System32\SpaceAgent.exe",
		"%windir%\System32\spaceman.exe",
		"%windir%\System32\speech_onecore\common\SpeechModelDownload.exe",
		"%windir%\System32\speech_onecore\common\SpeechRuntime.exe",
		"%windir%\System32\srtasks.exe",
		"%windir%\System32\srvinitconfig.exe",
		"%windir%\System32\tzsync.exe",
		"%windir%\System32\UNP\UpdateNotificationMgr.exe",
		"%windir%\System32\wermgr.exe",
		"%WinDir%\System32\WinBioPlugIns\FaceFodUninstaller.exe",
		"%windir%\System32\WindowsActionDialog.exe",
		"%windir%\System32\wpcmon.exe",
		"%windir%\System32\XblGameSaveTask.exe",
		"BthUdTask.exe",
		"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
		"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe",
		"C:\Program Files\Microsoft Office\root\Office16\sdxhelper.exe",
		"C:\Program Files\Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16\operfmon.exe",
		"C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe",
		"C:\Program Files\NVIDIA Corporation\nview\nwiz.exe",
		"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
		'"C:\Windows\System32\MicTray64.exe"',
		"C:\Windows\System32\sc.exe",
		'"C:\Windows\System32\SynaMonApp.exe"'
    )

    $default_task_args = @(
		"config upnphost start= auto",
		'%systemroot%\System32\pla.dll,PlaHost "Server Manager Performance Monitor" "$(Arg0)"',
		'/B /nologo %systemroot%\System32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)',
		'/NoUACCheck'
    )

    ForEach ($task in $tasks){
        # Detection - Non-Standard Tasks
        ForEach ($i in $default_task_exe_paths){
            if ( $task.Execute -like $i) {
                $exe_match = $true
                break
            } elseif ($task.Execute.Length -gt 0) { 
                $exe_match = $false 
            }
        }

        # Task Running as SYSTEM
        if ($task.RunAs -eq "SYSTEM" -and $exe_match -eq $false -and $task.Arguments -notin $default_task_args) {
            # Current Task Executable Path is non-standard
            $detection = [PSCustomObject]@{
                Name = 'Non-Standard Scheduled Task Running as SYSTEM'
                Risk = 'High'
                Source = 'Scheduled Tasks'
                Technique = "T1053: Scheduled Task/Job"
                Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
            }
            Write-Detection $detection
            continue
        }
        # Detection - Task contains an IP Address
        if ($task.Execute -match $ipv4_pattern -or $task.Execute -match $ipv6_pattern) {
            # Task Contains an IP Address
            $detection = [PSCustomObject]@{
                Name = 'Scheduled Task contains an IP Address'
                Risk = 'High'
                Source = 'Scheduled Tasks'
                Technique = "T1053: Scheduled Task/Job"
                Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
            }
            Write-Detection $detection
        }
        # Task has suspicious terms
        $suspicious_keyword_regex = ".*(regsvr32.exe | downloadstring | mshta | frombase64 | tobase64 | EncodedCommand | DownloadFile | certutil | csc.exe | ieexec.exe | wmic.exe).*"
        if ($task.Execute -match $suspicious_keyword_regex -or $task.Arguments -match $suspicious_keyword_regex) {
            $detection = [PSCustomObject]@{
                Name = 'Scheduled Task contains suspicious keywords.'
                Risk = 'High'
                Source = 'Scheduled Tasks'
                Technique = "T1053: Scheduled Task/Job"
                Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
            }
            Write-Detection $detection
        }
        # Detection - User Created Tasks
        if ($task.Author -ne $null) {
            if (($task.Author).Contains("\")) {
                if ((($task.Author.Split('\')).count-1) -eq 1) {
                    if ($task.RunAs -eq "SYSTEM") {
                        # Current Task Executable Path is non-standard
                        $detection = [PSCustomObject]@{
                            Name = 'User-Created Task running as SYSTEM'
                            Risk = 'High'
                            Source = 'Scheduled Tasks'
                            Technique = "T1053: Scheduled Task/Job"
                            Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
                        }
                        Write-Detection $detection
                        continue
                    }
                    # Single '\' in author most likely indicates it is a user-made task
                    $detection = [PSCustomObject]@{
                        Name = 'User Created Task'
                        Risk = 'Low'
                        Source = 'Scheduled Tasks'
                        Technique = "T1053: Scheduled Task/Job"
                        Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
                    }
                    Write-Detection $detection
                }
            }
        }
        # Non-Standard EXE Path with Non-Default Argumentes
        if ($exe_match -eq $false -and $task.Arguments -notin $default_task_args) {
            # Current Task Executable Path is non-standard
            $detection = [PSCustomObject]@{
                Name = 'Non-Standard Scheduled Task Executable'
                Risk = 'Low'
                Source = 'Scheduled Tasks'
                Technique = "T1053: Scheduled Task/Job"
                Meta = "Task Name: "+ $task.TaskName+", Task Executable: "+ $task.Execute+", Arguments: "+$task.Arguments+", Task Author: "+ $task.Author+", RunAs: "+$task.RunAs
            }
            Write-Detection $detection
        }
    }
}

function Users {
    # Find all local administrators and their last logon time as well as if they are enabled.
    $local_admins = Get-LocalGroupMember -Group "Administrators" | Select-Object *
    ForEach ($admin in $local_admins){
        $admin_user = Get-LocalUser -SID $admin.SID | Select-Object AccountExpires,Description,Enabled,FullName,PasswordExpires,UserMayChangePassword,PasswordLastSet,LastLogon,Name,SID,PrincipalSource
        $detection = [PSCustomObject]@{
            Name = 'Local Administrator Account'
            Risk = 'Medium'
            Source = 'Users'
            Technique = "T1136: Create Account"
            Meta = "Name: "+$admin.Name +", Last Logon: "+ $admin_user.LastLogon+", Enabled: "+ $admin_user.Enabled
        }
        Write-Detection $detection
    }
    
}

function Services {
    $default_service_exe_paths = @(
		'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /medsvc',
		'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc',
		'"C:\Program Files (x86)\Microsoft\Edge\Application\*\elevation_service.exe"',
		'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /medsvc',
		'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc',
		'"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" /service',
		'"C:\Program Files\Google\Chrome\Application\*\elevation_service.exe"',
		'"C:\Program Files\Microsoft OneDrive\*\FileSyncHelper.exe"',
		'"C:\Program Files\Microsoft OneDrive\*\OneDriveUpdaterService.exe"',
		'"C:\Program Files\Microsoft Update Health Tools\uhssvc.exe"',
		'"C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe" -s NVDisplay.ContainerLocalSystem -f "C:\ProgramData\NVIDIA\NVDisplay.ContainerLocalSystem.log" -l 3 -d "C:\Program Files\NVIDIA Corporation\Display.NvContainer\plugins\LocalSystem" -r -p 30000 ',
		'"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"',
		'"C:\Program Files\Windows Media Player\wmpnetwk.exe"',
		'"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe"',
		'"C:\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe"',
		'"C:\Windows\CxSvc\CxAudioSvc.exe"',
		'"C:\Windows\CxSvc\CxUtilSvc.exe"',
		'"C:\Windows\System32\wbengine.exe"',
		'C:\Windows\Microsoft.Net\*\*\WPF\PresentationFontCache.exe',
		'C:\Windows\Microsoft.NET\Framework64\*\SMSvcHost.exe',
		'C:\Windows\servicing\TrustedInstaller.exe',
		'C:\Windows\System32\AgentService.exe',
		'C:\Windows\System32\alg.exe',
		'C:\Windows\System32\Alps\GlidePoint\HidMonitorSvc.exe',
		'C:\Windows\System32\AppVClient.exe',
		'C:\Windows\System32\cAVS\Intel(R) Audio Service\IntelAudioService.exe',
		'C:\Windows\System32\CredentialEnrollmentManager.exe',
		'C:\Windows\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe',
		'C:\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_*\igfxCUIService.exe',
		'C:\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\HotKeyServiceUWP.exe',
		'C:\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\LanWlanWwanSwitchingServiceUWP.exe',
		'C:\Windows\System32\DriverStore\FileRepository\iaahcic.inf_amd64_*\RstMwService.exe',
		'C:\Windows\System32\DriverStore\FileRepository\igcc_dch.inf_amd64_*\OneApp.IGCC.WinService.exe',
		'C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHDCPSvc.exe',
		'C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHeciSvc.exe',
		'C:\Windows\System32\fxssvc.exe',
		'C:\Windows\System32\ibtsiva',
		'C:\Windows\System32\locator.exe',
		'C:\Windows\System32\lsass.exe',
		'C:\Windows\System32\msdtc.exe',
		'C:\Windows\System32\msiexec.exe /V',
		'C:\Windows\System32\nvwmi64.exe',
		'C:\Windows\System32\OpenSSH\ssh-agent.exe',
		'C:\Windows\System32\PerceptionSimulation\PerceptionSimulationService.exe',
		'C:\Windows\System32\RSoPProv.exe',
		'C:\Windows\System32\SearchIndexer.exe /Embedding',
		'C:\Windows\System32\SecurityHealthService.exe',
		'C:\Windows\System32\SensorDataService.exe',
		'C:\Windows\System32\SgrmBroker.exe',
		'C:\Windows\System32\snmptrap.exe',
		'C:\Windows\System32\spectrum.exe',
		'C:\Windows\System32\spoolsv.exe',
		'C:\Windows\System32\sppsvc.exe',
		'C:\Windows\System32\svchost.exe -k AarSvcGroup -p',
		'C:\Windows\System32\svchost.exe -k appmodel -p',
		'C:\Windows\System32\svchost.exe -k appmodel',
		'C:\Windows\System32\svchost.exe -k AppReadiness -p',
		'C:\Windows\System32\svchost.exe -k AppReadiness',
		'C:\Windows\System32\svchost.exe -k AssignedAccessManagerSvc',
		'C:\Windows\System32\svchost.exe -k autoTimeSvc',
		'C:\Windows\System32\svchost.exe -k AxInstSVGroup',
		'C:\Windows\System32\svchost.exe -k BcastDVRUserService',
		'C:\Windows\System32\svchost.exe -k BthAppGroup -p',
		'C:\Windows\System32\svchost.exe -k Camera',
		'C:\Windows\System32\svchost.exe -k CameraMonitor',
		'C:\Windows\System32\svchost.exe -k ClipboardSvcGroup -p',
		'C:\Windows\System32\svchost.exe -k CloudIdServiceGroup -p',
		'C:\Windows\System32\svchost.exe -k DcomLaunch -p',
		'C:\Windows\System32\svchost.exe -k DcomLaunch',
		'C:\Windows\System32\svchost.exe -k defragsvc',
		'C:\Windows\System32\svchost.exe -k DevicesFlow -p',
		'C:\Windows\System32\svchost.exe -k DevicesFlow',
		'C:\Windows\System32\svchost.exe -k diagnostics',
		'C:\Windows\System32\svchost.exe -k DialogBlockingService',
		'C:\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup',
		'C:\Windows\System32\svchost.exe -k ICService -p',
		'C:\Windows\System32\svchost.exe -k imgsvc',
		'C:\Windows\System32\svchost.exe -k KpsSvcGroup',
		'C:\Windows\System32\svchost.exe -k localService -p',
		'C:\Windows\System32\svchost.exe -k LocalService -p',
		'C:\Windows\System32\svchost.exe -k LocalService',
		'C:\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p',
		'C:\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation',
		'C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p',
		'C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted',
		'C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p',
		'C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork',
		'C:\Windows\System32\svchost.exe -k LocalServiceNoNetworkFirewall -p',
		'C:\Windows\System32\svchost.exe -k LocalServicePeerNet',
		'C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p',
		'C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted',
		'C:\Windows\System32\svchost.exe -k McpManagementServiceGroup',
		'C:\Windows\System32\svchost.exe -k netsvcs -p',
		'C:\Windows\System32\svchost.exe -k NetSvcs -p',
		'C:\Windows\System32\svchost.exe -k netsvcs',
		'C:\Windows\System32\svchost.exe -k NetworkService -p',
		'C:\Windows\System32\svchost.exe -k NetworkService',
		'C:\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p',
		'C:\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted -p',
		'C:\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted',
		'C:\Windows\System32\svchost.exe -k PeerDist',
		'C:\Windows\System32\svchost.exe -k print',
		'C:\Windows\System32\svchost.exe -k PrintWorkflow',
		'C:\Windows\System32\svchost.exe -k rdxgroup',
		'C:\Windows\System32\svchost.exe -k rpcss -p',
		'C:\Windows\System32\svchost.exe -k RPCSS -p',
		'C:\Windows\System32\svchost.exe -k SDRSVC',
		'C:\Windows\System32\svchost.exe -k smbsvcs',
		'C:\Windows\System32\svchost.exe -k smphost',
		'C:\Windows\System32\svchost.exe -k swprv',
		'C:\Windows\System32\svchost.exe -k termsvcs',
		'C:\Windows\System32\svchost.exe -k UdkSvcGroup',
		'C:\Windows\System32\svchost.exe -k UnistackSvcGroup',
		'C:\Windows\System32\svchost.exe -k utcsvc -p',
		'C:\Windows\System32\svchost.exe -k utcsvc',
		'C:\Windows\System32\svchost.exe -k WbioSvcGroup',
		'C:\Windows\System32\svchost.exe -k WepHostSvcGroup',
		'C:\Windows\System32\svchost.exe -k WerSvcGroup',
		'C:\Windows\System32\svchost.exe -k wsappx -p',
		'C:\Windows\System32\svchost.exe -k wsappx',
		'C:\Windows\System32\svchost.exe -k wusvcs -p',
		'C:\Windows\System32\TieringEngineService.exe',
		'C:\Windows\System32\UI0Detect.exe',
		'C:\Windows\System32\vds.exe',
		'C:\Windows\System32\vssvc.exe',
		'C:\Windows\System32\wbem\WmiApSrv.exe',
		'C:\Windows\SysWow64\perfhost.exe',
		'C:\Windows\SysWOW64\XtuService.exe'    )

    $services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State

    ForEach ($service in $services){
        # Detection - Non-Standard Tasks
        ForEach ($i in $default_service_exe_paths){
            if ( $service.PathName -like $i) {
                $exe_match = $true
                break
            } elseif ($service.PathName.Length -gt 0) { 
                $exe_match = $false 
            }
        }
        if ($exe_match -eq $false) {
            # Current Task Executable Path is non-standard
            $detection = [PSCustomObject]@{
                Name = 'Non-Standard Service Path'
                Risk = 'Low'
                Source = 'Services'
                Technique = "T1543.003: Create or Modify System Process: Windows Service"
                Meta = "Service Name: "+ $service.Name+", Service Path: "+ $service.PathName
            }
            Write-Detection $detection
        }
        if ($service.PathName -match ".*cmd.exe /(k|c).*") {
            # Service has a suspicious launch pattern
            $detection = [PSCustomObject]@{
                Name = 'Service launching from cmd.exe'
                Risk = 'Medium'
                Source = 'Services'
                Technique = "T1543.003: Create or Modify System Process: Windows Service"
                Meta = "Service Name: "+ $service.Name+", Service Path: "+ $service.PathName
            }
            Write-Detection $detection
        }
        if ($service.PathName -match ".*powershell.exe.*") {
            # Service has a suspicious launch pattern
            $detection = [PSCustomObject]@{
                Name = 'Service launching from powershell.exe'
                Risk = 'Medium'
                Source = 'Services'
                Technique = "T1543.003: Create or Modify System Process: Windows Service"
                Meta = "Service Name: "+ $service.Name+", Service Path: "+ $service.PathName
            }
            Write-Detection $detection
        }
    }
}

function Processes {
    # TODO - Check for processes spawned from netsh.dll
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName,CreationDate,CommandLine,ExecutablePath,ParentProcessId,ProcessId
    ForEach ($process in $processes){
        if ($process.CommandLine -match $ipv4_pattern -or $process.CommandLine -match $ipv6_pattern) {
            $detection = [PSCustomObject]@{
                Name = 'IP Address Pattern detected in Process CommandLine'
                Risk = 'Medium'
                Source = 'Processes'
                Technique = "T1059: Command and Scripting Interpreter"
                Meta = "Process Name: "+ $process.ProcessName+", CommandLine: "+ $process.CommandLine+", Executable: "+$process.ExecutablePath
            }
            Write-Detection $detection
        }
        ForEach ($path in $suspicious_process_paths) {
            if ($process.ExecutablePath -match $path){
                $detection = [PSCustomObject]@{
                    Name = 'Suspicious Executable Path on Running Process'
                    Risk = 'High'
                    Source = 'Processes'
                    Technique = "T1059: Command and Scripting Interpreter"
                    Meta = "Process Name: "+ $process.ProcessName+", CommandLine: "+ $process.CommandLine+", Executable: "+$process.ExecutablePath
                }
                Write-Detection $detection
            }
        }

    }
}

function Connections {
    $tcp_connections = Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort
    $suspicious_ports = @(20,21,22,23,25,137,139,445,3389,443)
    $allow_listed_process_names = @(
		"brave",
		"chrome",
		"Discord",
		"firefox",
		"GitHubDesktop",
		"iexplorer",
		"msedge",
		"officeclicktorun"
		"OneDrive",
		"safari",
		"SearchApp",
		"Spotify",
		"steam"		
    )
    ForEach ($conn in $tcp_connections) {
        $proc = Get-Process -Id $conn.OwningProcess | Select-Object Name,Path
        if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024){
            $detection = [PSCustomObject]@{
                Name = 'Process Listening on Ephemeral Port'
                Risk = 'Very Low'
                Source = 'Connections'
                Technique = "T1071: Application Layer Protocol"
                Meta = "Local Port: "+$conn.LocalPort+", PID: "+$conn.OwningProcess+", Process Name: "+$proc.Name+", Process Path: "+$proc.Path
            }
            Write-Detection $detection
        }
        if ($conn.State -eq 'Established' -and ($conn.LocalPort -in $suspicious_ports -or $conn.RemotePort -in $suspicious_ports) -and $proc.Name -notin $allow_listed_process_names){
            $detection = [PSCustomObject]@{
                Name = 'Established Connection on Suspicious Port'
                Risk = 'Low'
                Source = 'Connections'
                Technique = "T1071: Application Layer Protocol"
                Meta = "Local Port: "+$conn.LocalPort+", Remote Port: "+$conn.RemotePort+", Remote Address: "+$conn.RemoteAddress+", PID: "+$conn.OwningProcess+", Process Name: "+$proc.Name+", Process Path: "+$proc.Path
            }
            Write-Detection $detection
        }
        if ($proc.Path -ne $null){
            ForEach ($path in $suspicious_process_paths){
                if (($proc.Path).ToLower() -match $path){
                    $detection = [PSCustomObject]@{
                        Name = 'Process running from suspicious path has Network Connection'
                        Risk = 'High'
                        Source = 'Connections'
                        Technique = "T1071: Application Layer Protocol"
                        Meta = "Local Port: "+$conn.LocalPort+", Remote Port: "+$conn.RemotePort+", Remote Address: "+$conn.RemoteAddress+", PID: "+$conn.OwningProcess+", Process Name: "+$proc.Name+", Process Path: "+$proc.Path
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}

function WMI-Consumers {
    $consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object *

    ForEach ($consumer in $consumers) {
        if ($consumer.ScriptingEngine -ne $null) {
            $detection = [PSCustomObject]@{
                Name = 'WMI ActiveScript Consumer'
                Risk = 'High'
                Source = 'WMI'
                Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
                Meta = "Consumer Name: "+$consumer.Name+", Script Name: "+$consumer.ScriptFileName+", Script Text: "+$consumer.ScriptText
            }
            Write-Detection $detection
        }
        if ($consumer.CommandLineTemplate -ne $null) {
            $detection = [PSCustomObject]@{
                Name = 'WMI CommandLine Consumer'
                Risk = 'High'
                Source = 'WMI'
                Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
                Meta = "Consumer Name: "+$consumer.Name+", Executable Path: "+$consumer.ExecutablePath+", CommandLine Template: "+$consumer.CommandLineTemplate
            }
            Write-Detection $detection
        }
    }
}

function Startups {
    $startups = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command,Location,Name,User
    ForEach ($item in $startups) {
        $detection = [PSCustomObject]@{
            Name = 'Startup Item Review'
            Risk = 'Low'
            Source = 'Startup'
            Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
            Meta = "Item Name: "+$item.Name+", Command: "+$item.Command+", Location: "+$item.Location+", User: "+$item.User
        }
        Write-Detection $detection
    }
}

function BITS {
    $bits = Get-BitsTransfer | Select-Object JobId,DisplayName,TransferType,JobState,OwnerAccount
    ForEach ($item in $bits) {
        $detection = [PSCustomObject]@{
            Name = 'BITS Item Review'
            Risk = 'Low'
            Source = 'BITS'
            Technique = "T1197: BITS Jobs"
            Meta = "Item Name: "+$item.DisplayName+", TransferType: "+$item.TransferType+", Job State: "+$item.JobState+", User: "+$item.OwnerAccount
        }
        Write-Detection $detection
    }
}

function Modified-Windows-Accessibility-Feature {
    $files_to_check = @(
		"C:\Program Files\Common Files\microsoft shared\ink\HID.dll"
		"C:\Windows\System32\AtBroker.exe",
		"C:\Windows\System32\DisplaySwitch.exe",
		"C:\Windows\System32\Magnify.exe",
		"C:\Windows\System32\Narrator.exe",
		"C:\Windows\System32\osk.exe",
		"C:\Windows\System32\sethc.exe",
		"C:\Windows\System32\utilman.exe"		
    )
    ForEach ($file in $files_to_check){ 
        $fdata = Get-Item $file -ErrorAction SilentlyContinue | Select-Object CreationTime,LastWriteTime
        if ($fdata.CreationTime -ne $null) {
            if ($fdata.CreationTime.ToString() -ne $fdata.LastWriteTime.ToString()){
                $detection = [PSCustomObject]@{
                    Name = 'Potential modification of Windows Accessibility Feature'
                    Risk = 'High'
                    Source = 'Windows'
                    Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
                    Meta = "File: "+$file+", Created: "+$fdata.CreationTime+", Modified: "+$fdata.LastWriteTime
                }
                Write-Detection $detection
            }
        }
    }
}

function PowerShell-Profiles {
    # PowerShell profiles may be abused by adversaries for persistence.

    # $PSHOME\Profile.ps1
    # $PSHOME\Microsoft.PowerShell_profile.ps1
    # $HOME\Documents\PowerShell\Profile.ps1
    # $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
    $PROFILE | Select-Object AllUsersAllHosts,AllUsersCurrentHost,CurrentUserAllHosts,CurrentUserCurrentHost | Out-Null
    if (Test-Path $PROFILE.AllUsersAllHosts){
        $detection = [PSCustomObject]@{
            Name = 'Custom PowerShell Profile for All Users should be reviewed.'
            Risk = 'Medium'
            Source = 'Windows'
            Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
            Meta = "Profile: "+$PROFILE.AllUsersAllHosts
        }
        Write-Detection $detection
    }
    if (Test-Path $PROFILE.AllUsersCurrentHost){
        $detection = [PSCustomObject]@{
            Name = 'Custom PowerShell Profile for All Users should be reviewed.'
            Risk = 'Medium'
            Source = 'Windows'
            Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
            Meta = "Profile: "+$PROFILE.AllUsersCurrentHost
        }
        Write-Detection $detection
    }

    $profile_names = Get-ChildItem 'C:\Users' -Attributes Directory | Select-Object Name
    ForEach ($name in $profile_names){
        $path1 = "C:\Users\$name\Documents\WindowsPowerShell\profile.ps1"
        $path2 = "C:\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
        $path3 = "C:\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        if (Test-Path $path1){
            $detection = [PSCustomObject]@{
                Name = 'Custom PowerShell Profile for Specific User should be reviewed.'
                Risk = 'Medium'
                Source = 'Windows'
                Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
                Meta = "Profile: "+$path1
            }
            Write-Detection $detection
        }
        if (Test-Path $path2){
            $detection = [PSCustomObject]@{
                Name = 'Custom PowerShell Profile for Specific User should be reviewed.'
                Risk = 'Medium'
                Source = 'Windows'
                Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
                Meta = "Profile: "+$path2
            }
            Write-Detection $detection
        }
        if (Test-Path $path3){
            $detection = [PSCustomObject]@{
                Name = 'Custom PowerShell Profile for Specific User should be reviewed.'
                Risk = 'Medium'
                Source = 'Windows'
                Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
                Meta = "Profile: "+$path3
            }
            Write-Detection $detection
        }
    }
}

function Office-Startup {
    $profile_names = Get-ChildItem 'C:\Users' -Attributes Directory | Select-Object *
    ForEach ($user in $profile_names){
        $path = "C:\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Word\STARTUP"
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in ".wll",".xll",".ppam",".ppa",".dll",".vsto",".vba"}
        ForEach ($item in $items){
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Office Startup Addin'
                Risk = 'Medium'
                Source = 'Windows'
                Technique = "T1137.006: Office Application Startup: Add-ins"
                Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
            }
            Write-Detection $detection
        }
        $path = "C:\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
        if (Test-Path $path) {
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Outlook Application Startup'
                Risk = 'Medium'
                Source = 'Windows'
                Technique = "T1137.006: Office Application Startup: Add-ins"
                Meta = "File: "+$path
            }
            Write-Detection $detection
        }
    }
}

function Registry-Checks {

    # SilentProcessExit Persistence
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.MonitorProcess -ne $null){
                if ($data.ReportingMode -eq $null){
                    $data.ReportingMode = 'NA'
                }
                $detection = [PSCustomObject]@{
                    Name = 'Process Launched on SilentProcessExit'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
                    Meta = "Monitored Process: "+$item.Name+", Launched Process: "+$data.MonitorProcess+", Reporting Mode: "+$data.ReportingMode
                }
                Write-Detection $detection
            }
        }
    }

    # Winlogon Helper DLL Hijack
    $standard_winlogon_helper_dlls = @(
        "C:\Windows\System32\userinit.exe," # Server 2019
    )
    if (Test-Path -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        $items = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Value -match '.*,.*' -and $_.Value -notin $standard_winlogon_helper_dlls) {
                $detection = [PSCustomObject]@{
                    Name = 'Potential WinLogon Helper Persistence'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL"
                    Meta = "Key Location: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe") {
            $detection = [PSCustomObject]@{
                Name = 'Potential utilman.exe Registry Persistence'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
                Meta = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
            }
            Write-Detection $detection
    }

    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe") {
            $detection = [PSCustomObject]@{
                Name = 'Potential sethc.exe Registry Persistence'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
                Meta = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
            }
            Write-Detection $detection
    }

    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Shadow' -and ($_.Value -eq 4 -or $_.Value -eq 2)) {
                $detection = [PSCustomObject]@{
                    Name = 'RDP Shadowing without Consent is Enabled'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1098: Account Manipulation"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'LocalAccountTokenFilterPolicy' -and $_.Value -eq 1) {
                $detection = [PSCustomObject]@{
                    Name = 'UAC Disabled for Remote Sessions'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1112: Modify Registry"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    $standard_print_monitors = @(
		"APMon.dll",
		"AppMon.dll",
		"FXSMON.dll",
		"localspl.dll",
		"tcpmon.dll",
		"usbmon.dll",
		"WSDMon.dll" # Server 2016
    )
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($data.Driver -notin $standard_print_monitors){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Monitor DLL'
                        Risk = 'Medium'
                        Source = 'Registry'
                        Technique = "T1112: Modify Registry"
                        Meta = "Registry Path: "+$item.Name+", System32 DLL: "+$data.Driver
                    }
                    Write-Detection $detection
                }
            }
        }
    }


    # LSA Security Package Review
    # TODO - Check DLL Modification/Creation times
    $common_ssp_dlls = @(
		"cloudAP", # Server 2016
		"ctxauth", #citrix
		"kerberos",
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
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                ForEach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Security Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
                            Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: "+$_.Name+", Entry Value: "+$_.Value+", Abnormal Package: "+$package
                        }
                        Write-Detection $detection
                    }
                }
            }
            if ($_.Name -eq 'Authentication Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                ForEach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Authentication Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.002: Boot or Logon Autostart Execution: Authentication Packages"
                            Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: "+$_.Name+", Entry Value: "+$_.Value+", Abnormal Package: "+$package
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                ForEach ($package in $packages){
                    if ($package -notin $common_ssp_dlls){
                        $detection = [PSCustomObject]@{
                            Name = 'LSA Security Package Review'
                            Risk = 'Medium'
                            Source = 'Registry'
                            Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
                            Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: "+$_.Name+", Entry Value: "+$_.Value+", Abnormal Package: "+$package
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }

    # Time Provider Review
    $standard_timeprovider_dll = @(
        "C:\Windows\System32\w32time.dll",
        "C:\Windows\System32\vmictimeprovider.dll"
    )
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.DllName -ne $null){
                if ($standard_timeprovider_dll -notcontains $data.DllName){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Time Providers DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.003: Boot or Logon Autostart Execution: Time Providers"
                        Meta = "Registry Path: "+$item.Name+", DLL: "+$data.DllName
                    }
                    Write-Detection $detection
                }
            }
        }
    }

    # T1547.012 - Boot or Logon Autostart Execution: Print Processors
    $standard_print_processors = @(
        "winprint.dll"
    )
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($standard_print_processors -notcontains $data.Driver){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Processor DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
                        Meta = "Registry Path: "+$item.Name+", DLL: "+$data.Driver
                    }
                    Write-Detection $detection
                }
            }
        }
    }
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Driver -ne $null){
                if ($standard_print_processors -notcontains $data.Driver){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard Print Processor DLL'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
                        Meta = "Registry Path: "+$item.Name+", DLL: "+$data.Driver
                    }
                    Write-Detection $detection
                }
            }
        }
    }

    # T1547.014 - Boot or Logon Autostart Execution: Active Setup
    $standard_stubpaths = @(
		"/UserInstall",
		'"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', # Server 2016
		"C:\Windows\System32\ie4uinit.exe -UserConfig", # 10
		"C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install", # 10
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', # Server 2019
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', # Server 2019
		"C:\Windows\System32\unregmp2.exe /FirstLogon", # 10
		"C:\Windows\System32\unregmp2.exe /ShowWMP", # 10
		"U"
    )
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components") {
        $items = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.StubPath -ne $null){
                if ($standard_stubpaths -notcontains $data.StubPath -and $data.StubPath -notmatch ".*(\\Program Files\\Google\\Chrome\\Application\\.*chrmstp.exe|Microsoft\\Edge\\Application\\.*\\Installer\\setup.exe).*"){
                    $detection = [PSCustomObject]@{
                        Name = 'Non-Standard StubPath Executed on User Logon'
                        Risk = 'High'
                        Source = 'Registry'
                        Technique = "T1547.014: Boot or Logon Autostart Execution: Active Setup"
                        Meta = "Registry Path: "+$item.Name+", StubPath: "+$data.StubPath
                    }
                    Write-Detection $detection
                }
            }
        }
    }

    # T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)
    if (Test-Path -Path "Registry::HKCU\Environment\UserInitMprLogonScript") {
        $items = Get-ItemProperty -Path "Registry::HKCU\Environment\UserInitMprLogonScript" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Logon Initialization Script'
                Risk = 'Medium'
                Source = 'Registry'
                Technique = "T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)"
                Meta = "Key Location: HKCU\Environment\UserInitMprLogonScript, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
            }
            Write-Detection $detection
        }
    }

    #TODO - Inspect File Command Extensions to hunt for anomalies
    # https://attack.mitre.org/techniques/T1546/001/


    # T1546.002 - Event Triggered Execution: Screensaver
    if (Test-Path -Path "Registry::HKCU\Control Panel\Desktop") {
        $items = Get-ItemProperty -Path "Registry::HKCU\Control Panel\Desktop" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "SCRNSAVE.exe") {
                $detection = [PSCustomObject]@{
                    Name = 'Potential Persistence via ScreenSaver Executable Hijack'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.002: Event Triggered Execution: Screensaver"
                    Meta = "Key Location: HKCU\Control Panel\Desktop, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # T1546.007 - Event Triggered Execution: Netsh Helper DLL
    $standard_netsh_dlls = @(
		"authfwcfg.dll",
		"dhcpcmonitor.dll",
		"dot3cfg.dll",
		"fwcfg.dll",
		"hnetmon.dll",
		"ifmon.dll",
		"netiohlp.dll",
		"netprofm.dll",
		"nettrace.dll",
		"nshhttp.dll",
		"nshipsec.dll",
		"nshwfp.dll",
		"p2pnetsh.dll",
		"peerdistsh.dll",
		"rasmontr.dll",
		"rpcnsh.dll",
		"WcnNetsh.dll",
		"whhelper.dll",
		"wlancfg.dll",
		"wshelper.dll",
		"wwancfg.dll"
    )
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Microsoft\Netsh") {
        $items = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Netsh" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Value -notin $standard_netsh_dlls) {
                $detection = [PSCustomObject]@{
                    Name = 'Potential Persistence via Netsh Helper DLL Hijack'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.007: Event Triggered Execution: Netsh Helper DLL"
                    Meta = "Key Location: HKLM\SOFTWARE\Microsoft\Netsh, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # AppCertDLL
    $standard_appcert_dlls = @()
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Value -notin $standard_appcert_dlls) {
                $detection = [PSCustomObject]@{
                    Name = 'Potential Persistence via AppCertDLL Hijack'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.009: Event Triggered Execution: AppCert DLLs"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # AppInit DLLs

    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
                $detection = [PSCustomObject]@{
                    Name = 'Potential AppInit DLL Persistence'
                    Risk = 'Medium'
                    Source = 'Registry'
                    Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }      
                Write-Detection $detection
            }
        }
    }
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
                $detection = [PSCustomObject]@{
                    Name = 'Potential AppInit DLL Persistence'
                    Risk = 'Medium'
                    Source = 'Registry'
                    Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }      
                Write-Detection $detection
            }
        }
    }

    # Shims
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Potential Application Shimming Persistence'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1546.011: Event Triggered Execution: Application Shimming"
                Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
            }      
            Write-Detection $detection
        }
    }

    # IFEO Injection
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") {
        $items = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Debugger -ne $null){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Image File Execution Option Debugger Injection'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
                    Meta = "Registry Path: "+$item.Name+", Debugger: "+$data.Debugger
                }
                Write-Detection $detection
            }
        }
    }
    # COM Hijacks
    # shell32.dll Hijack
    if (Test-Path -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32") {
        $items = Get-ItemProperty -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Potential shell32.dll Hijack for Persistence'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
                Meta = "Key Location: HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
            }      
            Write-Detection $detection
        }
    }
    # WBEM Subsystem
    if (Test-Path -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32") {
        $items = Get-ItemProperty -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Potential WBEM Subsystem Hijack for Persistence'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
                Meta = "Key Location: HKCU\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
            }      
            Write-Detection $detection
        }
    }

    # COM Object Hijack Scan
    if (Test-Path -Path "Registry::HKCU\SOFTWARE\Classes\CLSID") {
        $items = Get-ChildItem -Path "Registry::HKCU\SOFTWARE\Classes\CLSID" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $children = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            ForEach ($child in $children){
                $path = "Registry::"+$child.Name
                $data = Get-Item -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
                if ($data.Name -match '.*InprocServer32'){
                    $datum = Get-ItemProperty $path
                    $datum.PSObject.Properties | ForEach-Object {
                        if ($_.Name -eq '(default)'){
                            $detection = [PSCustomObject]@{
                                Name = 'Potential COM Hijack'
                                Risk = 'High'
                                Source = 'Registry'
                                Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
                                Meta = "Registry Path: "+$data.Name+", DLL Path: "+$_.Value
                            }
                            Write-Detection $detection
                        }
                    }
                }
            }
        }
    }

    # Folder Open Hijack
    if (Test-Path -Path "Registry::HKCU\Software\Classes\Folder\shell\open\command") {
        $items = Get-ItemProperty -Path "Registry::HKCU\Software\Classes\Folder\shell\open\command" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'DelegateExecute') {
                $detection = [PSCustomObject]@{
                    Name = 'Potential Folder Open Hijack for Persistence'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
                    Meta = "Key Location: HKCU\Software\Classes\Folder\shell\open\command, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }      
                Write-Detection $detection
            }
        }
    }

    # TODO - Inspect Parameters for https://attack.mitre.org/techniques/T1574/011/

    # T1556.002: Modify Authentication Process: Password Filter DLL
    # TODO - Check DLL Modification/Creation times
    $standard_lsa_notification_packages = @(
		"rassfm", # Windows Server 2019 AWS Lightsail
		"scecli" # Windows 10/Server
    )
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "Notification Packages") {
                $packages = $_.Value.Split([System.Environment]::NewLine)
                ForEach ($package in $packages){
                    if ($package -notin $standard_lsa_notification_packages){
                        $detection = [PSCustomObject]@{
                            Name = 'Potential Exploitation via Password Filter DLL'
                            Risk = 'High'
                            Source = 'Registry'
                            Technique = "T1556.002: Modify Authentication Process: Password Filter DLL"
                            Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                        }
                        Write-Detection $detection
                    }
                }
            }
        }
    }

    # Office test Persistence
    if (Test-Path -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf") {
        $items = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Persistence via Office test\Special\Perf Key'
                Risk = 'Very High'
                Source = 'Registry'
                Technique = "T1137.002: Office Application Startup: Office Test"
                Meta = "Key Location: HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf: "+$_.Name+", Entry Value: "+$_.Value
            }      
            Write-Detection $detection
        }
    }
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            $detection = [PSCustomObject]@{
                Name = 'Persistence via Office test\Special\Perf Key'
                Risk = 'Very High'
                Source = 'Registry'
                Technique = "T1137.002: Office Application Startup: Office Test"
                Meta = "Key Location: HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
            }      
            Write-Detection $detection
        }
    }

    # Office GlobalDotName Hijack
    $office_versions = @(14.0,15.0,16.0)
    ForEach ($version in $office_versions){
        if (Test-Path -Path "Registry::HKCU\software\microsoft\office\$version.0\word\options") {
            $items = Get-ItemProperty -Path "Registry::HKCU\software\microsoft\office\$version.0\word\options" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq "GlobalDotName"){
                    $detection = [PSCustomObject]@{
                        Name = 'Persistence via Office GlobalDotName'
                        Risk = 'Very High'
                        Source = 'Registry'
                        Technique = "T1137.001: Office Application Office Template Macros"
                        Meta = "Key Location: HKCU\software\microsoft\office\$version.0\word\options, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                    }      
                    Write-Detection $detection
                }
            }
        }
    }

    # Terminal Services DLL
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'ServiceDll' -and $_.Value -ne 'C:\Windows\System32\termsrv.dll'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Terminal Services DLL'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1505.005: Server Software Component: Terminal Services DLL"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }      
                Write-Detection $detection
            }
        }
    }

    # Autodial DLL
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'AutodialDLL' -and $_.Value -ne 'C:\Windows\System32\rasadhlp.dll'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Autodial DLL'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # Command AutoRun Processor
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'AutoRun'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Command AutoRun Processor'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    if (Test-Path -Path "Registry::HKCU\SOFTWARE\Microsoft\Command Processor") {
        $items = Get-ItemProperty -Path "Registry::HKCU\SOFTWARE\Microsoft\Command Processor" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'AutoRun'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Command AutoRun Processor'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: HKCU\SOFTWARE\Microsoft\Command Processor, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # Trust Provider Hijacking
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}") {
        $items = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Dll' -and $_.Value -ne 'C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Trust Provider'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1553: Subvert Trust Controls"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
            if ($_.Name -eq 'FuncName' -and $_.Value -ne 'PsVerifyHash'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Hijacking of Trust Provider'
                    Risk = 'Very High'
                    Source = 'Registry'
                    Technique = "T1553: Subvert Trust Controls"
                    Meta = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
}

function LNK-Scan {
    $current_date = Get-Date
    $WScript = New-Object -ComObject WScript.Shell
    $profile_names = Get-ChildItem 'C:\Users' -Attributes Directory | Select-Object *
    ForEach ($user in $profile_names){
        $path = "C:\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Windows\Recent"
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object {$_.extension -in ".lnk"} | Select-Object *
        ForEach ($item in $items){
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
                        Source = 'Windows'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = "LNK File: "+$item.FullName+", LNK Target: "+$lnk_target+", Last Write Time: "+$item.LastWriteTime
                    }
                    Write-Detection $detection
                }
                if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*"){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains multiple file extensions'
                        Risk = 'Medium'
                        Source = 'Windows'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = "LNK File: "+$item.FullName+", LNK Target: "+$lnk_target+", Last Write Time: "+$item.LastWriteTime
                    }
                    Write-Detection $detection
                }

            }
        }
    }
}

function Process-Module-Scanning {
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName,CreationDate,CommandLine,ExecutablePath,ParentProcessId,ProcessId
    ForEach ($process in $processes){

        $suspicious_unsigned_dll_names = @(
			"cdpsgshims.dll",
			"diagtrack_win.dll",
			"EdgeGdi.dll",
			"Msfte.dll",
			"phoneinfo.dll",
			"Tsmsisrv.dll",
			"TSVIPSrv.dll",
			"Ualapi.dll",
			"wbemcomn.dll",
			"WindowsCoreDeviceInfo.dll",
			"windowsperformancerecordercontrol.dll",
			"wlanhlp.dll",
			"wlbsctrl.dll",
			"wow64log.dll",
			"WptsExtensions.dll"
        )
        $modules = Get-Process -id $process.ProcessId -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty modules -ErrorAction SilentlyContinue | Select-Object Company,FileName,ModuleName
        if ($modules -ne $null){
            ForEach ($module in $modules){
                if ($module.ModuleName -in $suspicious_unsigned_dll_names) {
                    $signature = Get-AuthenticodeSignature $module.FileName
                    if ($signature.Status -ne 'Valid'){
                        $item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
                        $detection = [PSCustomObject]@{
                            Name = 'Suspicious Unsigned DLL with commonly-masqueraded name loaded into running process.'
                            Risk = 'Very High'
                            Source = 'Windows'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = "DLL: "+$module.FileName+", Process Name: "+$process.ProcessName+", PID: "+$process.ProcessId+", Execuable Path: "+$process.ExecutablePath+", DLL Creation Time: "+$item.CreationTime+", DLL Last Write Time: "+$item.LastWriteTime
                        }
                        Write-Detection $detection
                    } else {
                        $item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
                        $detection = [PSCustomObject]@{
                            Name = 'Suspicious DLL with commonly-masqueraded name loaded into running process.'
                            Risk = 'High'
                            Source = 'Windows'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = "DLL: "+$module.FileName+", Process Name: "+$process.ProcessName+", PID: "+$process.ProcessId+", Execuable Path: "+$process.ExecutablePath+", DLL Creation Time: "+$item.CreationTime+", DLL Last Write Time: "+$item.LastWriteTime
                        }
                        # TODO - This is too noisy to use as-is - these DLLs get loaded into quite a few processes.
                        # Write-Detection $detection
                    }
                }
            }
        }
    }
}

function Scan-Windows-Unsigned-Files
{
    $scan_paths = @(
    'C:\Windows',
    'C:\Windows\System32',
    'C:\Windows\System'
    'C:\Windows\temp'
    )
    ForEach ($path in $scan_paths)
    {
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".dll", ".exe" } | Select-Object *
        ForEach ($file in $files)
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
                    Meta = "File: " + $file.FullName + ", Creation Time: " + $item.CreationTime + ", Last Write Time: " + $item.LastWriteTime
                }
                #Write-Host $detection.Meta
                Write-Detection $detection
            }
        }
    }
}


function Write-Detection($det)  {
    # det is a custom object which will contain various pieces of metadata for the detection
    # Name - The name of the detection logic.
    # Risk (Very Low, Low, Medium, High, Very High)
    # Source - The source 'module' reporting the detection
    # Technique - The most relevant MITRE Technique
    # Meta - String containing reference material specific to the received detection
    if ($det.Risk -eq 'Very Low' -or $det.Risk -eq 'Low') {
        $fg_color = 'Green'
    } elseif ($det.Risk -eq 'Medium'){
        $fg_color = 'Yellow'
    } elseif ($det.Risk -eq 'High') {
        $fg_color = 'Red'
    } elseif ($det.Risk -eq 'Very High') {
        $fg_color = 'Magenta'
    }
    Write-Host [+] New Detection: $det.Name - Risk: $det.Risk -ForegroundColor $fg_color
    Write-Host [%] $det.Meta -ForegroundColor White
    if ($output_writable){
       $det | Export-CSV $outpath -Append -NoTypeInformation -Encoding UTF8
    }
}

function Logo {
    $logo = "
  __________  ___ _       ____    __________ 
 /_  __/ __ \/   | |     / / /   / ____/ __ \
  / / / /_/ / /| | | /| / / /   / __/ / /_/ /
 / / / _, _/ ___ | |/ |/ / /___/ /___/ _, _/ 
/_/ /_/ |_/_/  |_|__/|__/_____/_____/_/ |_|  
    "
    Write-Host $logo -ForegroundColor White
    Write-Host "Trawler - Dredging Windows for Persistence" -ForegroundColor White
    Write-Host "github.com/joeavanzato/trawler" -ForegroundColor White
    Write-Host ""
}

function Main {
    Logo
    Scheduled-Tasks
    Users
    services
    Processes
    Connections
    WMI-Consumers
    Startups
    BITS
    Modified-Windows-Accessibility-Feature
    PowerShell-Profiles
    Office-Startup
    Registry-Checks
    LNK-Scan
    Process-Module-Scanning
    Scan-Windows-Unsigned-Files
}

Main