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
$suspicious_terms = ".*(\[System\.Reflection\.Assembly\]|regedit|invoke|frombase64|tobase64|rundll32|http:|https:|system\.net\.webclient|downloadfile|downloadstring|bitstransfer|system\.net\.sockets|tcpclient|xmlhttp|AssemblyBuilderAccess|shellcode|rc4bytestream|disablerealtimemonitoring|wmiobject|wmimethod|remotewmi|wmic|gzipstream|::decompress|io\.compression|write-zip|encodedcommand|wscript\.shell|MSXML2\.XMLHTTP).*"

$ipv4_pattern = '.*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*'
$ipv6_pattern = '.*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*'
$office_addin_extensions = ".wll",".xll",".ppam",".ppa",".dll",".vsto",".vba", ".xlam", ".com"

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
        # TODO - Task contains domain-pattern

        # Task has suspicious terms
        $suspicious_keyword_regex = ".*(regsvr32.exe | downloadstring | mshta | frombase64 | tobase64 | EncodedCommand | DownloadFile | certutil | csc.exe | ieexec.exe | wmic.exe).*"
        if ($task.Execute -match $suspicious_keyword_regex -or $task.Arguments -match $suspicious_keyword_regex) {
            $detection = [PSCustomObject]@{
                Name = 'Scheduled Task contains suspicious keywords'
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

        if ($service.PathName -match $suspicious_keyword_regex) {
            # Service has a suspicious launch pattern
            $detection = [PSCustomObject]@{
                Name = 'Service launching with suspicious keywords'
                Risk = 'High'
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
                Source = 'Network Connections'
                Technique = "T1071: Application Layer Protocol"
                Meta = "Local Port: "+$conn.LocalPort+", PID: "+$conn.OwningProcess+", Process Name: "+$proc.Name+", Process Path: "+$proc.Path
            }
            Write-Detection $detection
        }
        if ($conn.State -eq 'Established' -and ($conn.LocalPort -in $suspicious_ports -or $conn.RemotePort -in $suspicious_ports) -and $proc.Name -notin $allow_listed_process_names){
            $detection = [PSCustomObject]@{
                Name = 'Established Connection on Suspicious Port'
                Risk = 'Low'
                Source = 'Network Connections'
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
                        Source = 'Network Connections'
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
            Source = 'PowerShell'
            Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
            Meta = "Profile: "+$PROFILE.AllUsersAllHosts
        }
        Write-Detection $detection
    }
    if (Test-Path $PROFILE.AllUsersCurrentHost){
        $detection = [PSCustomObject]@{
            Name = 'Custom PowerShell Profile for All Users should be reviewed.'
            Risk = 'Medium'
            Source = 'PowerShell'
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
                Source = 'PowerShell'
                Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
                Meta = "Profile: "+$path1
            }
            Write-Detection $detection
        }
        if (Test-Path $path2){
            $detection = [PSCustomObject]@{
                Name = 'Custom PowerShell Profile for Specific User should be reviewed.'
                Risk = 'Medium'
                Source = 'PowerShell'
                Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
                Meta = "Profile: "+$path2
            }
            Write-Detection $detection
        }
        if (Test-Path $path3){
            $detection = [PSCustomObject]@{
                Name = 'Custom PowerShell Profile for Specific User should be reviewed.'
                Risk = 'Medium'
                Source = 'PowerShell'
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
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
        ForEach ($item in $items){
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Office Startup Addin'
                Risk = 'Medium'
                Source = 'Office'
                Technique = "T1137.006: Office Application Startup: Add-ins"
                Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
            }
            #Write-Detection $detection - Removing this as it is a duplicate of the new Office Scanning Functionality which will cover the same checks
        }
        $path = "C:\Users\"+$user.Name+"\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
        if (Test-Path $path) {
            $detection = [PSCustomObject]@{
                Name = 'Potential Persistence via Outlook Application Startup'
                Risk = 'Medium'
                Source = 'Office'
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

    # Winlogon Helper DLL Hijacks
    $standard_winlogon_helper_dlls = @(
        "C:\Windows\System32\userinit.exe,"
        "explorer.exe"
        "sihost.exe"
        "ShellAppRuntime.exe"
        "mpnotify.exe"
    )
    if (Test-Path -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        $items = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -in 'Userinit','Shell','ShellInfrastructure','ShellAppRuntime','MPNotify' -and $_.Value -notin $standard_winlogon_helper_dlls) {
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
    # TODO - Also check HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
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
    # TODO - Add HKLM COM Scanning

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
                Source = 'Office'
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
                Source = 'Office'
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
                        Source = 'Office'
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

    # NLP Development Platform Hijacks
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Language") {
        $items = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Language" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.StemmerDLLPathOverride -ne $null -or $data.WBDLLPathOverride){
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
                    Meta = "Registry Path: "+$item.Name+", DLL: "+$dll
                }
                Write-Detection $detection
            }
        }
    }

    # Debugger Hijacks
    # AeDebug 32
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p"){
                $detection = [PSCustomObject]@{
                    Name = 'Potential AeDebug Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # AeDebug 64
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p"){
                $detection = [PSCustomObject]@{
                    Name = 'Potential AeDebug Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # .NET 32
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d"){
                $detection = [PSCustomObject]@{
                    Name = 'Potential .NET Debugger Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # .NET 64
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d"){
                $detection = [PSCustomObject]@{
                    Name = 'Potential .NET Debugger Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # Microsoft Script Debugger
    $path = "HKEY_CLASSES_ROOT\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq '@' -and ($_.Value -ne "`"$env:homedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env:homedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Microsoft Script Debugger Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # Process Debugger
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{78A51822-51F4-11D0-8F20-00805F2CD064}\InprocServer32"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if (($_.Name -in '(default)' -and $_.Value -ne "$env:homedrive\Program Files\Common Files\Microsoft Shared\VS7Debug\pdm.dll") -or ($_.Name -eq '@' -and $_.Value -ne "`"$env:homedrive\WINDOWS\system32\pdm.dll`"")){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Process Debugger Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }
    # WER Debuggers
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -in 'Debugger','ReflectDebugger'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential WER Debugger Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # Windows Load Key
    $path = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    if (Test-Path -Path "Registry::$path") {
        $item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $item.PSObject.Properties | ForEach-Object {
            if ($_.Name -in 'Load'){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Windows Load Hijacking'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1546: Event Triggered Execution"
                    Meta = "Key Location: $path, Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                }
                Write-Detection $detection
            }
        }
    }

    # App Path Hijacks
    $path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    if (Test-Path -Path "Registry::$path") {
        $items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $data.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq '(default)') {
                    $key_basename = [regex]::Matches($item.Name, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]
                    $value_basename = [regex]::Matches($_.Value, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]
                    if ($key_basename -ne $null -and $value_basename -ne $null){
                        $value_basename = $value_basename.Replace('"', "")
                        if ($key_basename -ne $value_basename){
                            $detection = [PSCustomObject]@{
                                Name = 'Potential App Path Hijacking'
                                Risk = 'Medium'
                                Source = 'Registry'
                                Technique = "T1546: Event Triggered Execution"
                                Meta = "Key Location: "+$item.Name+", Entry Name: "+$_.Name+", Entry Value: "+$_.Value
                            }
                            Write-Detection $detection
                        }
                    }
                }
            }
        }
    }

    # Service DLL Inspection
    $path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
    $homedrive = $env:homedrive
    $image_path_lookup = @{
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ZoomCptService" = "`"$homedrive\\Program Files\\Common Files\\Zoom\\Support\\CptService\.exe`" -user_path `"$homedrive\\Users\\.*\\AppData\\Roaming\\Zoom`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xinputhid" = "\\SystemRoot\\System32\\drivers\\xinputhid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" = "$homedrive\\Windows\\system32\\svchost.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci" = "\\SystemRoot\\System32\\drivers\\1394ohci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware" = "System32\\drivers\\3ware\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k AarSvcGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k AarSvcGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI" = "System32\\drivers\\ACPI\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev" = "\\SystemRoot\\System32\\drivers\\AcpiDev\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex" = "System32\\Drivers\\acpiex\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr" = "\\SystemRoot\\System32\\drivers\\acpipagr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi" = "\\SystemRoot\\System32\\drivers\\acpipmi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime" = "\\SystemRoot\\System32\\drivers\\acpitime\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000" = "system32\\drivers\\Acx01000\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX" = "System32\\drivers\\ADP80XX\.SYS"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD" = "\\SystemRoot\\system32\\drivers\\afd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix" = "\\SystemRoot\\system32\\drivers\\afunix\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache" = "system32\\DRIVERS\\ahcache\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG" = "$homedrive\\Windows\\System32\\alg\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdgpio2" = "\\SystemRoot\\System32\\drivers\\amdgpio2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdi2c" = "\\SystemRoot\\System32\\drivers\\amdi2c\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8" = "\\SystemRoot\\System32\\drivers\\amdk8\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM" = "\\SystemRoot\\System32\\drivers\\amdppm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata" = "System32\\drivers\\amdsata\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs" = "System32\\drivers\\amdsbs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata" = "System32\\drivers\\amdxata\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID" = "system32\\drivers\\appid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppleKmdfFilter" = "\\SystemRoot\\System32\\drivers\\AppleKmdfFilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppleLowerFilter" = "\\SystemRoot\\System32\\drivers\\AppleLowerFilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr" = "system32\\drivers\\applockerfltr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness" = "$homedrive\\Windows\\System32\\svchost\.exe -k AppReadiness -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient" = "$homedrive\\Windows\\system32\\AppVClient\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm" = "\\SystemRoot\\system32\\drivers\\AppvStrm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr" = "\\SystemRoot\\system32\\drivers\\AppvVemgr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs" = "\\SystemRoot\\system32\\drivers\\AppvVfs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k wsappx -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas" = "System32\\drivers\\arcsas\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ArmouryCrateService" = "`"$homedrive\\Program Files\\ASUS\\ARMOURY CRATE Lite Service\\ArmouryCrate\.Service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\asComSvc" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\AXSP\\4\.02\.15\\atkexComSvc\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k AssignedAccessManagerSvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\asus" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\Update\\AsusUpdate\.exe`" /svc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsusCertService" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\AsusCertService\\AsusCertService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsusFanControlService" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\AsusFanControlService\\2\.03\.08\\AsusFanControlService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Asusgio2" = "\\??\\$homedrive\\Windows\\system32\\drivers\\AsIO2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Asusgio3" = "\\??\\$homedrive\\Windows\\system32\\drivers\\AsIO3\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\asusm" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\Update\\AsusUpdate\.exe`" /medsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsusUpdateCheck" = "$homedrive\\Windows\\System32\\AsusUpdateCheck\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac" = "\\SystemRoot\\System32\\drivers\\asyncmac\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi" = "System32\\drivers\\atapi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atvi-randgrid_sr" = "\\??\\D:\\SteamLibrary\\steamapps\\common\\Call of Duty HQ\\randgrid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k autoTimeSvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV" = "$homedrive\\Windows\\system32\\svchost\.exe -k AxInstSVGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv" = "System32\\drivers\\bxvbda\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam" = "system32\\drivers\\bam\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay\.inf_amd64_fc93ae411c02f280\\BasicDisplay\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicrender\.inf_amd64_ed345fdc37d65139\\BasicRender\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" = "$homedrive\\Windows\\system32\\svchost\.exe -k BcastDVRUserService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k BcastDVRUserService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcmfn2" = "\\SystemRoot\\System32\\drivers\\bcmfn2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BEService" = "`"$homedrive\\Program Files \(x86\)\\Common Files\\BattlEye\\BEService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNoNetworkFirewall -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt" = "\\SystemRoot\\system32\\drivers\\bindflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" = "$homedrive\\Windows\\system32\\svchost\.exe -k BthAppGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k BthAppGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser" = "system32\\DRIVERS\\bowser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp" = "\\SystemRoot\\System32\\drivers\\BthA2dp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum" = "\\SystemRoot\\System32\\drivers\\BthEnum\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum" = "\\SystemRoot\\System32\\drivers\\bthhfenum\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum" = "\\SystemRoot\\System32\\drivers\\Microsoft\.Bluetooth\.Legacy\.LEEnumerator\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini" = "\\SystemRoot\\System32\\drivers\\BTHMINI\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM" = "\\SystemRoot\\System32\\drivers\\bthmodem\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthPan" = "\\SystemRoot\\System32\\drivers\\bthpan\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT" = "\\SystemRoot\\System32\\drivers\\BTHport\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB" = "\\SystemRoot\\System32\\drivers\\BTHUSB\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt" = "System32\\drivers\\bttflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter" = "\\SystemRoot\\System32\\drivers\\buttonconverter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CAD" = "\\SystemRoot\\System32\\drivers\\CAD\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k appmodel -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k ClipboardSvcGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k ClipboardSvcGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs" = "system32\\DRIVERS\\cdfs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom" = "\\SystemRoot\\System32\\drivers\\cdrom\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi" = "System32\\drivers\\cht4sx64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd" = "\\SystemRoot\\System32\\drivers\\cht4vx64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\circlass" = "\\SystemRoot\\System32\\drivers\\circlass\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt" = "system32\\drivers\\cldflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS" = "System32\\drivers\\CLFS\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClickToRunSvc" = "`"$homedrive\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun\.exe`" /service"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC" = "$homedrive\\Windows\\System32\\svchost\.exe -k wsappx -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k CloudIdServiceGroup -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt" = "\\SystemRoot\\System32\\drivers\\CmBatt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG" = "System32\\Drivers\\cng\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist" = "System32\\DRIVERS\\cnghwassist\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\com.docker.service" = "`"$homedrive\\Program Files\\Docker\\Docker\\com\.docker\.service`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\compositebus\.inf_amd64_7500cffa210c6946\\CompositeBus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp" = "$homedrive\\Windows\\system32\\dllhost\.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv" = "System32\\drivers\\condrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNoNetwork -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairGamingAudioConfig" = "$homedrive\\Windows\\System32\\CorsairGamingAudioCfgService64\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairGamingAudioService" = "\\??\\$homedrive\\Windows\\System32\\drivers\\CorsairGamingAudio64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairLLAccessC2D033F14715AA7325305EA42FBFC65BF867CC1D" = "\\??\\$homedrive\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\CorsairLLAccess64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairLLAService" = "`"$homedrive\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\CueLLAccessService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairService" = "`"$homedrive\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\Corsair\.Service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairUniwillService" = "`"$homedrive\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\CueUniwillService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairVBusDriver" = "\\SystemRoot\\System32\\drivers\\CorsairVBusDriver\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CorsairVHidDriver" = "\\SystemRoot\\System32\\drivers\\CorsairVHidDriver\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cpuz152" = "\\??\\$homedrive\\Windows\\temp\\cpuz152\\cpuz152_x64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cpuz153" = "\\??\\$homedrive\\Windows\\temp\\cpuz153\\cpuz153_x64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cpuz154" = "\\??\\$homedrive\\Windows\\temp\\cpuz154\\cpuz154_x64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" = "$homedrive\\Windows\\system32\\CredentialEnrollmentManager\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_1af30d" = "$homedrive\\Windows\\system32\\CredentialEnrollmentManager\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC" = "system32\\drivers\\csc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CTIAIO" = "\\??\\$homedrive\\Windows\\system32\\drivers\\CtiAIo64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam" = "system32\\drivers\\dam\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dbupdate" = "`"$homedrive\\Program Files \(x86\)\\Dropbox\\Update\\DropboxUpdate\.exe`" /svc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dbupdatem" = "`"$homedrive\\Program Files \(x86\)\\Dropbox\\Update\\DropboxUpdate\.exe`" /medsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DbxSvc" = "$homedrive\\Windows\\system32\\DbxSvc\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dc1-controller" = "\\SystemRoot\\System32\\drivers\\dc1-controller\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dcsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k defragsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k DevicesFlow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc" = "System32\\Drivers\\dfsc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" = "$homedrive\\Windows\\system32\\DiagSvcs\\DiagnosticsHub\.StandardCollector\.Service\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k diagnostics"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" = "$homedrive\\Windows\\System32\\svchost\.exe -k utcsvc -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService" = "$homedrive\\Windows\\system32\\svchost\.exe -k DialogBlockingService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk" = "System32\\drivers\\disk\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc" = "\\SystemRoot\\System32\\drivers\\dmvsc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNoNetwork -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud" = "\\SystemRoot\\System32\\drivers\\drmkaud\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl" = "\\SystemRoot\\System32\\drivers\\dxgkrnl\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e2fexpress" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\e2f68\.inf_amd64_6f3569c398020b3a\\e2f68\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eaphost" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EasyAntiCheat" = "`"$homedrive\\Program Files \(x86\)\\EasyAntiCheat\\EasyAntiCheat\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS" = "`"$homedrive\\Program Files \(x86\)\\EasyAntiCheat_EOS\\EasyAntiCheat_EOS\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv" = "System32\\drivers\\evbda\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate" = "`"$homedrive\\Program Files \(x86\)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate\.exe`" /svc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" = "`"$homedrive\\Program Files \(x86\)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate\.exe`" /medsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS" = "$homedrive\\Windows\\System32\\lsass\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass" = "System32\\drivers\\EhStorClass\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv" = "System32\\drivers\\EhStorTcgDrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k appmodel -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev" = "\\SystemRoot\\System32\\drivers\\errdev\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fax" = "$homedrive\\Windows\\system32\\fxssvc\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc" = "\\SystemRoot\\System32\\drivers\\fdc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt" = "system32\\drivers\\filecrypt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo" = "System32\\drivers\\fileinfo\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileSyncHelper" = "`"$homedrive\\Program Files\\Microsoft OneDrive\\23\.071\.0402\.0001\\FileSyncHelper\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace" = "system32\\drivers\\filetrace\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk" = "\\SystemRoot\\System32\\drivers\\flpydisk\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr" = "system32\\drivers\\fltmgr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" = "$homedrive\\Windows\\Microsoft\.Net\\Framework64\\v3\.0\\WPF\\PresentationFontCache\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer" = "$homedrive\\Windows\\System32\\svchost\.exe -k Camera"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends" = "System32\\drivers\\FsDepends\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fvevol" = "System32\\DRIVERS\\fvevol\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FvSvc" = "`"$homedrive\\Program Files\\NVIDIA Corporation\\FrameViewSDK\\nvfvsdksvc_x64\.exe`" -service"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GameSDK Service" = "`"$homedrive\\Program Files \(x86\)\\ASUS\\GameSDK Service\\GameSDK\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter" = "\\SystemRoot\\System32\\drivers\\vmgencounter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\genericusbfn\.inf_amd64_53931f0ae21d6d2c\\genericusbfn\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" = "`"$homedrive\\Program Files\\Google\\Chrome\\Application\\112\.0\.5615\.137\\elevation_service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\googledrivefs31092" = "system32\\DRIVERS\\googledrivefs31092\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101" = "System32\\Drivers\\msgpioclx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" = "System32\\drivers\\gpuenergydrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k GraphicsPerfSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate" = "`"$homedrive\\Program Files \(x86\)\\Google\\Update\\GoogleUpdate\.exe`" /svc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem" = "`"$homedrive\\Program Files \(x86\)\\Google\\Update\\GoogleUpdate\.exe`" /medsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hcmon" = "\\SystemRoot\\system32\\DRIVERS\\hcmon\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService" = "\\SystemRoot\\System32\\drivers\\HdAudio\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus" = "\\SystemRoot\\System32\\drivers\\HDAudBus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt" = "\\SystemRoot\\System32\\drivers\\HidBatt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth" = "\\SystemRoot\\System32\\drivers\\hidbth\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c" = "\\SystemRoot\\System32\\drivers\\hidi2c\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt" = "\\SystemRoot\\System32\\drivers\\hidinterrupt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidIr" = "\\SystemRoot\\System32\\drivers\\hidir\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi" = "\\SystemRoot\\System32\\drivers\\hidspi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb" = "\\SystemRoot\\System32\\drivers\\hidusb\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetSvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hnswfpdriver" = "System32\\drivers\\hnswfpdriver\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD" = "System32\\drivers\\HpSAMD\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP" = "system32\\drivers\\HTTP\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash" = "\\SystemRoot\\System32\\drivers\\hvcrash\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice" = "system32\\drivers\\hvservice\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvsocketcontrol" = "\\SystemRoot\\system32\\drivers\\hvsocketcontrol\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101" = "System32\\Drivers\\mshwnclx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy" = "System32\\drivers\\hwpolicy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd" = "\\SystemRoot\\System32\\drivers\\hyperkbd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo" = "\\SystemRoot\\System32\\drivers\\HyperVideo\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt" = "\\SystemRoot\\System32\\drivers\\i8042prt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iagpio" = "\\SystemRoot\\System32\\drivers\\iagpio\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iai2c" = "\\SystemRoot\\System32\\drivers\\iai2c\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_GPIO2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_GPIO2_BXT_P\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_CNL" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_GPIO2_CNL\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_GLK" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_GPIO2_GLK\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_I2C\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_I2C_BXT_P\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_CNL" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_I2C_CNL\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_GLK" = "\\SystemRoot\\System32\\drivers\\iaLPSS2i_I2C_GLK\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO" = "\\SystemRoot\\System32\\drivers\\iaLPSSi_GPIO\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C" = "\\SystemRoot\\System32\\drivers\\iaLPSSi_I2C\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC" = "System32\\drivers\\iaStorAVC\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV" = "System32\\drivers\\iaStorV\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus" = "\\SystemRoot\\System32\\drivers\\ibbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtusb" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\ibtusb\.inf_amd64_f75065d93521b024\\ibtusb\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iCUEDevicePluginHost" = "`"$homedrive\\Program Files\\Corsair\\CORSAIR iCUE 4 Software\\iCUEDevicePluginHost\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd" = "\\SystemRoot\\System32\\drivers\\IndirectKmd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide" = "System32\\drivers\\intelide\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep" = "System32\\drivers\\intelpep\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpmax" = "\\SystemRoot\\System32\\drivers\\intelpmax\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm" = "\\SystemRoot\\System32\\drivers\\intelppm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate" = "system32\\drivers\\iorate\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver" = "system32\\DRIVERS\\ipfltdrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetSvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV" = "\\SystemRoot\\System32\\drivers\\IPMIDrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT" = "System32\\drivers\\ipnat\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT" = "\\SystemRoot\\System32\\drivers\\ipt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp" = "System32\\drivers\\isapnp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt" = "\\SystemRoot\\System32\\drivers\\msiscsi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i" = "System32\\drivers\\ItSas35i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\JetBrainsEtwHost.16" = "`"$homedrive\\Program Files\\JetBrains\\ETW Host\\16\\JetBrains\.Etw\.Collector\.Host\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\jhi_service" = "$homedrive\\Windows\\System32\\DriverStore\\FileRepository\\dal\.inf_amd64_b5484efd38adbe8d\\jhi_service\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass" = "\\SystemRoot\\System32\\drivers\\kbdclass\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid" = "\\SystemRoot\\System32\\drivers\\kbdhid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbldfltr" = "system32\\drivers\\kbldfltr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic" = "\\SystemRoot\\System32\\drivers\\kdnic\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso" = "$homedrive\\Windows\\system32\\lsass\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD" = "System32\\Drivers\\ksecdd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg" = "System32\\Drivers\\ksecpkg\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk" = "\\SystemRoot\\system32\\drivers\\ksthunk\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\l2bridge" = "System32\\drivers\\l2bridge\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LGHUBUpdaterService" = "`"$homedrive\\Program Files\\LGHUB\\lghub_updater\.exe`" --run-as-service"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LightingService" = "`"$homedrive\\Program Files \(x86\)\\LightingService\\LightingService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio" = "system32\\drivers\\lltdio\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_generic_hid_filter" = "\\SystemRoot\\system32\\drivers\\logi_generic_hid_filter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_joy_bus_enum" = "\\SystemRoot\\system32\\drivers\\logi_joy_bus_enum\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_joy_hid_filter" = "\\SystemRoot\\system32\\drivers\\logi_joy_hid_filter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_joy_hid_lo" = "\\SystemRoot\\system32\\drivers\\logi_joy_hid_lo\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_joy_vir_hid" = "\\SystemRoot\\system32\\drivers\\logi_joy_vir_hid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\logi_joy_xlcore" = "\\SystemRoot\\system32\\drivers\\logi_joy_xlcore\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS" = "System32\\drivers\\lsi_sas\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i" = "System32\\drivers\\lsi_sas2i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i" = "System32\\drivers\\lsi_sas3i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SSS" = "System32\\drivers\\lsi_sss\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv" = "\\SystemRoot\\system32\\drivers\\luafv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lxss" = "system32\\drivers\\lxss\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManagerUser" = "$homedrive\\Windows\\system32\\svchost\.exe -k LxssManagerUser -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManagerUser_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k LxssManagerUser -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost" = "\\SystemRoot\\System32\\drivers\\mausbhost\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip" = "\\SystemRoot\\System32\\drivers\\mausbip\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MBAMChameleon" = "\\SystemRoot\\System32\\Drivers\\MbamChameleon\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbamElam" = "system32\\DRIVERS\\MbamElam\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MBAMService" = "`"$homedrive\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MBAMSwissArmy" = "\\SystemRoot\\System32\\Drivers\\mbamswissarmy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbbCx" = "system32\\drivers\\MbbCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService" = "$homedrive\\Windows\\system32\\svchost\.exe -k McpManagementServiceGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas" = "System32\\drivers\\megasas\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i" = "System32\\drivers\\MegaSas2i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i" = "System32\\drivers\\megasas35i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr" = "System32\\drivers\\megasr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MEIx64" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\heci\.inf_amd64_c22251d5ea82b3c3\\x64\\TeeDriverW10x64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" = "`"$homedrive\\Program Files \(x86\)\\Microsoft\\Edge\\Application\\112\.0\.1722\.48\\elevation_service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport" = "\\SystemRoot\\System32\\drivers\\Microsoft\.Bluetooth\.AvrcpTransport\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus" = "\\SystemRoot\\System32\\drivers\\mlx4_bus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS" = "\\SystemRoot\\system32\\drivers\\mmcss\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem" = "system32\\drivers\\modem\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MongoDB" = "`"$homedrive\\Program Files\\MongoDB\\Server\\6\.0\\bin\\mongod\.exe`" --config `"$homedrive\\Program Files\\MongoDB\\Server\\6\.0\\bin\\mongod\.cfg`" --service"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor" = "\\SystemRoot\\System32\\drivers\\monitor\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass" = "\\SystemRoot\\System32\\drivers\\mouclass\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid" = "\\SystemRoot\\System32\\drivers\\mouhid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr" = "System32\\drivers\\mountmgr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv" = "System32\\drivers\\mpsdrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNoNetworkFirewall -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MRxDAV" = "\\SystemRoot\\system32\\drivers\\mrxdav\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb" = "system32\\DRIVERS\\mrxsmb\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20" = "system32\\DRIVERS\\mrxsmb20\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge" = "System32\\drivers\\bridge\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC" = "$homedrive\\Windows\\System32\\msdtc\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32" = "\\SystemRoot\\System32\\drivers\\msgpiowin32\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf" = "\\SystemRoot\\System32\\drivers\\mshidkmdf\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf" = "\\SystemRoot\\System32\\drivers\\mshidumdf\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSIO" = "\\??\\$homedrive\\Windows\\system32\\drivers\\MsIo64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv" = "System32\\drivers\\msisadrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver" = "$homedrive\\Windows\\system32\\msiexec\.exe /V"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV" = "\\SystemRoot\\System32\\drivers\\MSKSSRV\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp" = "system32\\drivers\\mslldp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK" = "\\SystemRoot\\System32\\drivers\\MSPCLOCK\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM" = "\\SystemRoot\\System32\\drivers\\MSPQM\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic" = "system32\\drivers\\msquic\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore" = "system32\\drivers\\msseccore\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt" = "system32\\drivers\\mssecflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp" = "system32\\drivers\\mssecwfp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios" = "\\SystemRoot\\System32\\drivers\\mssmbios\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE" = "\\SystemRoot\\System32\\drivers\\MSTEE\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig" = "\\SystemRoot\\System32\\drivers\\MTConfig\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup" = "System32\\Drivers\\mup\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis" = "System32\\drivers\\mvumis\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP" = "system32\\DRIVERS\\nwifi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetSvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNoNetwork -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr" = "\\SystemRoot\\System32\\drivers\\ndfltr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS" = "system32\\drivers\\ndis\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap" = "System32\\drivers\\ndiscap\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform" = "System32\\drivers\\NdisImPlatform\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi" = "System32\\DRIVERS\\ndistapi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio" = "system32\\drivers\\ndisuio\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus" = "\\SystemRoot\\System32\\drivers\\NdisVirtualBus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan" = "\\SystemRoot\\System32\\drivers\\ndiswan\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy" = "System32\\DRIVERS\\ndiswan\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing" = "system32\\drivers\\NDKPing\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy" = "System32\\DRIVERS\\NDProxy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" = "system32\\drivers\\Ndu\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx" = "system32\\drivers\\NetAdapterCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS" = "system32\\drivers\\netbios\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT" = "System32\\DRIVERS\\netbt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" = "$homedrive\\Windows\\system32\\lsass\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" = "$homedrive\\Windows\\Microsoft\.NET\\Framework64\\v4\.0\.30319\\SMSvcHost\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc" = "\\SystemRoot\\System32\\drivers\\netvsc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netwtw10" = "\\SystemRoot\\System32\\drivers\\Netwtw10\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netwtw12" = "\\SystemRoot\\System32\\drivers\\Netwtw12\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npcap" = "\\SystemRoot\\system32\\DRIVERS\\npcap\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig" = "\\SystemRoot\\System32\\drivers\\npsvctrig\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy" = "system32\\drivers\\nsiproxy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvagent" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetSvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NvContainerLocalSystem" = "`"$homedrive\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer\.exe`" -s NvContainerLocalSystem -f `"$homedrive\\ProgramData\\NVIDIA\\NvContainerLocalSystem\.log`" -l 3 -d `"$homedrive\\Program Files\\NVIDIA Corporation\\NvContainer\\plugins\\LocalSystem`" -r -p 30000 -st `"$homedrive\\Program"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm" = "System32\\drivers\\nvdimm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NVDisplay.ContainerLocalSystem" = "$homedrive\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi\.inf_amd64_f840d03a202f8a32\\Display\.NvContainer\\NVDisplay\.Container\.exe -s NVDisplay\.ContainerLocalSystem -f $homedrive\\ProgramData\\NVIDIA\\NVDisplay\.ContainerLocalSystem\.log -l 3 -d $homedrive\\Windows\\System32\\Dr"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NVHDA" = "\\SystemRoot\\system32\\drivers\\nvhda64v\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\nv_dispi\.inf_amd64_f840d03a202f8a32\\nvlddmkm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NvModuleTracker" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\nvmoduletracker\.inf_amd64_0c1cc60a4b422185\\NvModuleTracker\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid" = "System32\\drivers\\nvraid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor" = "System32\\drivers\\nvstor\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvvad_WaveExtensible" = "\\SystemRoot\\system32\\drivers\\nvvad64v\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvvhci" = "\\SystemRoot\\System32\\drivers\\nvvhci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneDrive Updater Service" = "`"$homedrive\\Program Files\\Microsoft OneDrive\\23\.071\.0402\.0001\\OneDriveUpdaterService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServicePeerNet"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServicePeerNet"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9Rdr" = "System32\\drivers\\p9rdr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport" = "\\SystemRoot\\System32\\drivers\\parport\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr" = "System32\\drivers\\partmgr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\passthruparser" = "system32\\drivers\\passthruparser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci" = "System32\\drivers\\pci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide" = "System32\\drivers\\pciide\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia" = "System32\\drivers\\pcmcia\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw" = "System32\\drivers\\pcw\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc" = "system32\\drivers\\pdc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH" = "system32\\drivers\\peauth\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k PeerDist"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation" = "$homedrive\\Windows\\system32\\PerceptionSimulation\\PerceptionSimulationService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i" = "System32\\drivers\\percsas2i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i" = "System32\\drivers\\percsas3i\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost" = "$homedrive\\Windows\\SysWow64\\perfhost\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pgbouncer" = "$homedrive\\Program Files \(x86\)\\PgBouncer\\bin\\pgbouncer\.exe --service `"$homedrive\\Program Files \(x86\)\\PgBouncer\\share\\pgbouncer\.ini`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon" = "system32\\drivers\\PktMon\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNoNetwork -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Player Location Check" = "$homedrive\\Program Files \(x86\)\\GeoComply\\//PlayerLocationCheck///Application/service\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem" = "System32\\drivers\\pmem\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM" = "\\SystemRoot\\System32\\drivers\\pnpmem\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServicePeerNet"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServicePeerNet"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetworkServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg" = "\\SystemRoot\\System32\\drivers\\portcfg\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\postgresql-x64-14" = "`"$homedrive\\Program Files\\PostgreSQL\\14\\bin\\pg_ctl\.exe`" runservice -N `"postgresql-x64-14`" -D `"$homedrive\\Program Files\\PostgreSQL\\14\\data`" -w"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport" = "\\SystemRoot\\System32\\drivers\\raspptp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify" = "$homedrive\\Windows\\system32\\svchost\.exe -k print"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k PrintWorkflow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k PrintWorkflow"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrivateInternetAccessService" = "`"$homedrive\\Program Files\\Private Internet Access\\pia-service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrivateInternetAccessWireguard" = "`"$homedrive\\Program Files\\Private Internet Access\\pia-wgservice\.exe`" `"$homedrive\\Program Files\\Private Internet Access\\data\\wgpia0\.conf`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor" = "\\SystemRoot\\System32\\drivers\\processr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched" = "System32\\drivers\\pacer\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvhdparser" = "system32\\drivers\\pvhdparser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv" = "\\SystemRoot\\system32\\drivers\\qwavedrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RabbitMQ" = "`"$homedrive\\Program Files\\erl-24\.0\\erts-12\.0\\bin\\erlsrv\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk" = "system32\\DRIVERS\\ramdisk\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd" = "System32\\DRIVERS\\rasacd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn" = "\\SystemRoot\\System32\\drivers\\AgileVpn\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp" = "\\SystemRoot\\System32\\drivers\\rasl2tp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe" = "System32\\DRIVERS\\raspppoe\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp" = "\\SystemRoot\\System32\\drivers\\rassstp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss" = "system32\\DRIVERS\\rdbss\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus" = "\\SystemRoot\\System32\\drivers\\rdpbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR" = "System32\\drivers\\rdpdr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport" = "System32\\drivers\\rdpvideominiport\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdyboost" = "System32\\drivers\\rdyboost\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry" = "$homedrive\\Windows\\system32\\svchost\.exe -k localService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" = "$homedrive\\Windows\\System32\\svchost\.exe -k rdxgroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM" = "\\SystemRoot\\System32\\drivers\\rfcomm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy" = "\\SystemRoot\\System32\\drivers\\rhproxy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rockstar Service" = "`"$homedrive\\Program Files\\Rockstar Games\\Launcher\\RockstarService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ROG Live Service" = "`"$homedrive\\Program Files\\ASUS\\ROG Live Service\\ROGLiveService\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper" = "$homedrive\\Windows\\system32\\svchost\.exe -k RPCSS -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator" = "$homedrive\\Windows\\system32\\locator\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs" = "$homedrive\\Windows\\system32\\svchost\.exe -k rpcss -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr" = "system32\\drivers\\rspndr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap" = "\\SystemRoot\\System32\\drivers\\vms3cap\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs" = "$homedrive\\Windows\\system32\\lsass\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port" = "System32\\drivers\\sbp2port\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter" = "System32\\DRIVERS\\scfilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus" = "System32\\drivers\\scmbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus" = "\\SystemRoot\\System32\\drivers\\sdbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd" = "\\SystemRoot\\System32\\drivers\\SDFRd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC" = "$homedrive\\Windows\\system32\\svchost\.exe -k SDRSVC"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor" = "\\SystemRoot\\System32\\drivers\\sdstor\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService" = "$homedrive\\Windows\\system32\\SecurityHealthService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" = "`"$homedrive\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService" = "$homedrive\\Windows\\System32\\SensorDataService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx" = "system32\\drivers\\SerCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2" = "system32\\drivers\\SerCx2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum" = "\\SystemRoot\\System32\\drivers\\serenum\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial" = "\\SystemRoot\\System32\\drivers\\serial\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse" = "\\SystemRoot\\System32\\drivers\\sermouse\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy" = "\\SystemRoot\\System32\\drivers\\sfloppy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent" = "system32\\drivers\\SgrmAgent\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker" = "$homedrive\\Windows\\system32\\SgrmBroker\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2" = "System32\\drivers\\SiSRaid2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4" = "System32\\drivers\\sisraid4\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD" = "System32\\drivers\\SmartSAMD\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect" = "System32\\DRIVERS\\smbdirect\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost" = "$homedrive\\Windows\\System32\\svchost\.exe -k smphost"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" = "$homedrive\\Windows\\System32\\snmptrap\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser" = "system32\\drivers\\spaceparser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport" = "System32\\drivers\\spaceport\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter" = "System32\\drivers\\SpatialGraphFilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx" = "system32\\drivers\\SpbCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" = "$homedrive\\Windows\\system32\\spectrum\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" = "$homedrive\\Windows\\System32\\spoolsv\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc" = "$homedrive\\Windows\\system32\\sppsvc\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2" = "System32\\DRIVERS\\srv2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet" = "System32\\DRIVERS\\srvnet\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent" = "$homedrive\\Windows\\System32\\OpenSSH\\ssh-agent\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository" = "$homedrive\\Windows\\system32\\svchost\.exe -k appmodel -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Steam Client Service" = "`"$homedrive\\Program Files \(x86\)\\Common Files\\Steam\\steamservice\.exe`" /RunAsService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor" = "System32\\drivers\\stexstor\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k imgsvc"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci" = "System32\\drivers\\storahci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt" = "System32\\drivers\\vmstorfl\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme" = "System32\\drivers\\stornvme\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt" = "system32\\drivers\\storqosflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs" = "System32\\drivers\\storufs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc" = "System32\\drivers\\storvsc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsp" = "\\SystemRoot\\System32\\drivers\\storvsp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\swenum\.inf_amd64_16a14542b63c02af\\swenum\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv" = "$homedrive\\Windows\\System32\\svchost\.exe -k swprv"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Synth3dVsc" = "\\SystemRoot\\System32\\drivers\\Synth3dVsc\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker" = "$homedrive\\Windows\\system32\\svchost\.exe -k DcomLaunch -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tap-pia-0901" = "\\SystemRoot\\System32\\drivers\\tap-pia-0901\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip" = "System32\\drivers\\tcpip\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6" = "System32\\drivers\\tcpip\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg" = "System32\\drivers\\tcpipreg\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx" = "\\SystemRoot\\system32\\DRIVERS\\tdx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TeamViewer" = "`"$homedrive\\Program Files\\TeamViewer\\TeamViewer_Service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Telemetry" = "System32\\drivers\\IntelTA\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt" = "\\SystemRoot\\System32\\drivers\\terminpt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Test Service" = "$homedrive\\Program Files\\A Subfolder\\B Subfolder\\C Subfolder\\SomeExecutable\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService" = "$homedrive\\Windows\\system32\\TieringEngineService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM" = "\\SystemRoot\\System32\\drivers\\tpm\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller" = "$homedrive\\Windows\\servicing\\TrustedInstaller\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt" = "system32\\drivers\\tsusbflt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD" = "\\SystemRoot\\System32\\drivers\\TsUsbGD\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub" = "\\SystemRoot\\System32\\drivers\\tsusbhub\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel" = "System32\\drivers\\tunnel\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor" = "\\SystemRoot\\System32\\drivers\\uaspstor\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101" = "System32\\Drivers\\UcmCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101" = "System32\\Drivers\\UcmTcpciCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient" = "\\SystemRoot\\System32\\drivers\\UcmUcsiAcpiClient\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101" = "System32\\Drivers\\UcmUcsiCx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000" = "system32\\drivers\\ucx01000\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx" = "system32\\drivers\\udecx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs" = "system32\\DRIVERS\\udfs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k UdkSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UdkSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\uefi\.inf_amd64_c1628ffa62c8e54c\\UEFI\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver" = "\\SystemRoot\\system32\\drivers\\UevAgentDriver\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService" = "$homedrive\\Windows\\system32\\AgentService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000" = "system32\\drivers\\ufx01000\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\ufxchipidea\.inf_amd64_1c78775fffab6a0a\\UfxChipidea\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys" = "\\SystemRoot\\System32\\drivers\\ufxsynopsys\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc" = "`"$homedrive\\Program Files\\Microsoft Update Health Tools\\uhssvc\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\umbus\.inf_amd64_b78a9c5b6fd62c27\\umbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass" = "\\SystemRoot\\System32\\drivers\\umpass\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_1af30d" = "$homedrive\\Windows\\System32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urschipidea\.inf_amd64_78ad1c14e33df968\\urschipidea\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000" = "system32\\drivers\\urscx01000\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urssynopsys\.inf_amd64_057fa37902020500\\urssynopsys\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio" = "\\SystemRoot\\system32\\drivers\\usbaudio\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2" = "\\SystemRoot\\System32\\drivers\\usbaudio2\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp" = "\\SystemRoot\\System32\\drivers\\usbccgp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbcir" = "\\SystemRoot\\System32\\drivers\\usbcir\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci" = "\\SystemRoot\\System32\\drivers\\usbehci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub" = "\\SystemRoot\\System32\\drivers\\usbhub\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3" = "\\SystemRoot\\System32\\drivers\\UsbHub3\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci" = "\\SystemRoot\\System32\\drivers\\usbohci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint" = "\\SystemRoot\\System32\\drivers\\usbprint\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbrndis6" = "\\SystemRoot\\System32\\drivers\\usb80236\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser" = "\\SystemRoot\\System32\\drivers\\usbser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" = "\\SystemRoot\\System32\\drivers\\USBSTOR\.SYS"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci" = "\\SystemRoot\\System32\\drivers\\usbuhci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbvideo" = "\\SystemRoot\\System32\\Drivers\\usbvideo\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI" = "\\SystemRoot\\System32\\drivers\\USBXHCI\.SYS"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc" = "$homedrive\\Windows\\system32\\lsass\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxNetAdp" = "\\SystemRoot\\system32\\DRIVERS\\VBoxNetAdp6\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxNetLwf" = "\\SystemRoot\\system32\\DRIVERS\\VBoxNetLwf\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxSDS" = "`"$homedrive\\Program Files\\Oracle\\VirtualBox\\VBoxSDS\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxSup" = "\\SystemRoot\\system32\\DRIVERS\\VBoxSup\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxUSBMon" = "\\SystemRoot\\system32\\DRIVERS\\VBoxUSBMon\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot" = "System32\\drivers\\vdrvroot\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds" = "$homedrive\\Windows\\System32\\vds\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt" = "System32\\drivers\\VerifierExt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VfpExt" = "system32\\drivers\\vfpext\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp" = "\\SystemRoot\\System32\\drivers\\vhdmp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdparser" = "system32\\drivers\\vhdparser\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf" = "\\SystemRoot\\System32\\drivers\\vhf\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vid" = "\\SystemRoot\\System32\\drivers\\Vid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender" = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\vrd\.inf_amd64_81fbd405ff2470fc\\vrd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMAuthdService" = "`"$homedrive\\Program Files \(x86\)\\VMware\\VMware Workstation\\vmware-authd\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus" = "System32\\drivers\\vmbus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID" = "\\SystemRoot\\System32\\drivers\\VMBusHID\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbusr" = "\\SystemRoot\\System32\\drivers\\vmbusr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci" = "System32\\drivers\\vmci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmcompute" = "$homedrive\\Windows\\system32\\vmcompute\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid" = "\\SystemRoot\\System32\\drivers\\vmgid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat" = "$homedrive\\Windows\\system32\\svchost\.exe -k ICService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv" = "$homedrive\\Windows\\system32\\svchost\.exe -k ICService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMnetAdapter" = "\\SystemRoot\\system32\\DRIVERS\\vmnetadapter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMnetBridge" = "\\SystemRoot\\system32\\DRIVERS\\vmnetbridge\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMnetDHCP" = "$homedrive\\Windows\\SysWOW64\\vmnetdhcp\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMnetuserif" = "\\SystemRoot\\system32\\DRIVERS\\vmnetuserif\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmsmp" = "\\SystemRoot\\System32\\drivers\\vmswitch\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSNPXY" = "system32\\drivers\\VmsProxyHNic\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSNPXYMP" = "\\SystemRoot\\System32\\drivers\\VmsProxyHNic\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSP" = "System32\\drivers\\vmswitch\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VmsProxy" = "system32\\drivers\\VmsProxy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSF" = "System32\\drivers\\vmswitch\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSP" = "System32\\drivers\\vmswitch\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusb" = "\\SystemRoot\\System32\\drivers\\vmusb\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMUSBArbService" = "`"$homedrive\\Program Files \(x86\)\\Common Files\\VMware\\USB\\vmware-usbarbitrator64\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMware NAT Service" = "$homedrive\\Windows\\SysWOW64\\vmnat\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmx86" = "\\SystemRoot\\system32\\DRIVERS\\vmx86\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VOICEMOD_Driver" = "\\SystemRoot\\system32\\drivers\\mvvad\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr" = "System32\\drivers\\volmgr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx" = "System32\\drivers\\volmgrx\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap" = "System32\\drivers\\volsnap\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume" = "System32\\drivers\\volume\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci" = "System32\\drivers\\vpci\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpcivsp" = "\\SystemRoot\\System32\\drivers\\vpcivsp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid" = "System32\\drivers\\vsmraid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock" = "system32\\DRIVERS\\vsock\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS" = "$homedrive\\Windows\\system32\\vssvc\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150" = "`"$homedrive\\Program Files \(x86\)\\Microsoft Visual Studio\\Shared\\Common\\DiagnosticsHub\.Collection\.Service\\StandardCollector\.Service\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vstor2-mntapi20-shared" = "SysWOW64\\drivers\\vstor2-x64\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID" = "System32\\drivers\\vstxraid\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus" = "\\SystemRoot\\System32\\drivers\\vwifibus\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwififlt" = "System32\\drivers\\vwififlt\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifimp" = "\\SystemRoot\\System32\\drivers\\vwifimp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k wusvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen" = "\\SystemRoot\\System32\\drivers\\wacompen\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService" = "$homedrive\\Windows\\System32\\svchost\.exe -k appmodel -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp" = "System32\\DRIVERS\\wanarp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6" = "System32\\DRIVERS\\wanarp\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine" = "`"$homedrive\\Windows\\system32\\wbengine\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k WbioSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs" = "\\SystemRoot\\system32\\drivers\\wcifs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceAndNoImpersonation -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcnfs" = "\\SystemRoot\\system32\\drivers\\wcnfs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot" = "system32\\drivers\\wd\\WdBoot\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000" = "system32\\drivers\\Wdf01000\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter" = "system32\\drivers\\wd\\WdFilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdiwifi" = "system32\\DRIVERS\\wdiwifi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter" = "system32\\drivers\\WdmCompanionFilter\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv" = "system32\\drivers\\wd\\WdNisDrv\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" = "`"$homedrive\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4\.18\.2303\.8-0\\NisSrv\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" = "$homedrive\\Windows\\system32\\svchost\.exe -k WepHostSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport" = "$homedrive\\Windows\\System32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k WerSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS" = "System32\\drivers\\wfplwfs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount" = "system32\\drivers\\wimmount\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" = "`"$homedrive\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4\.18\.2303\.8-0\\MsMpEng\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT" = "system32\\drivers\\WindowsTrustedRT\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy" = "System32\\drivers\\WindowsTrustedRTProxy\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad" = "\\SystemRoot\\System32\\drivers\\winmad\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat" = "system32\\drivers\\winnat\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM" = "$homedrive\\Windows\\System32\\svchost\.exe -k NetworkService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB" = "\\SystemRoot\\System32\\drivers\\WinUSB\.SYS"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs" = "\\SystemRoot\\System32\\drivers\\winverbs\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi" = "\\SystemRoot\\System32\\drivers\\wmiacpi\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv" = "$homedrive\\Windows\\system32\\wbem\\WmiApSrv\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMIRegistrationService" = "$homedrive\\Windows\\System32\\DriverStore\\FileRepository\\mewmiprov\.inf_amd64_cad1db73e8c782a6\\WMIRegistrationService\.exe"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" = "`"$homedrive\\Program Files\\Windows Media Player\\wmpnetwk\.exe`""
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalService -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalService"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr" = "System32\\drivers\\WpdUpFltr\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_1af30d" = "$homedrive\\Windows\\system32\\svchost\.exe -k UnistackSvcGroup"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl" = "\\SystemRoot\\system32\\drivers\\ws2ifsl\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" = "$homedrive\\Windows\\System32\\svchost\.exe -k LocalServiceNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch" = "$homedrive\\Windows\\system32\\SearchIndexer\.exe /Embedding"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf" = "system32\\drivers\\WudfPf\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd" = "\\SystemRoot\\System32\\drivers\\WUDFRd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFWpdFs" = "\\SystemRoot\\system32\\DRIVERS\\WUDFRd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFWpdMtp" = "\\SystemRoot\\system32\\DRIVERS\\WUDFRd\.sys"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc" = "$homedrive\\Windows\\system32\\svchost\.exe -k LocalSystemNetworkRestricted -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave" = "$homedrive\\Windows\\system32\\svchost\.exe -k netsvcs -p"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxgip" = "\\SystemRoot\\System32\\drivers\\xboxgip\.sys"
    }

    $service_dll_lookup = @{
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc\Parameters" = "$homedrive\\Windows\\System32\\AarSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter\Parameters" = "$homedrive\\Windows\\System32\\AJRouter\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc\Parameters" = "$homedrive\\Windows\\System32\\appidsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo\Parameters" = "$homedrive\\Windows\\System32\\appinfo\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt\Parameters" = "$homedrive\\Windows\\System32\\appmgmts\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness\Parameters" = "$homedrive\\Windows\\system32\\AppReadiness\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc\parameters" = "$homedrive\\Windows\\system32\\appxdeploymentserver\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc\Parameters" = "$homedrive\\Windows\\System32\\assignedaccessmanagersvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder\Parameters" = "$homedrive\\Windows\\System32\\AudioEndpointBuilder\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv\Parameters" = "$homedrive\\Windows\\System32\\Audiosrv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc\Parameters" = "$homedrive\\Windows\\System32\\autotimesvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV\Parameters" = "$homedrive\\Windows\\System32\\AxInstSV\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService\Parameters" = "$homedrive\\Windows\\System32\\BcastDVRUserService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC\Parameters" = "$homedrive\\Windows\\System32\\bdesvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters" = "$homedrive\\Windows\\System32\\bfe\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS\Parameters" = "$homedrive\\Windows\\System32\\qmgr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService\Parameters" = "$homedrive\\Windows\\System32\\Microsoft\.Bluetooth\.UserService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" = "$homedrive\\Windows\\System32\\psmsrv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters" = "$homedrive\\Windows\\System32\\BTAGService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc\Parameters" = "$homedrive\\Windows\\System32\\BthAvctpSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv\Parameters" = "$homedrive\\Windows\\system32\\bthserv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc\Parameters" = "$homedrive\\Windows\\system32\\CapabilityAccessManager\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService\Parameters" = "$homedrive\\Windows\\System32\\CaptureService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc\Parameters" = "$homedrive\\Windows\\System32\\cbdhsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc\Parameters" = "$homedrive\\Windows\\System32\\CDPSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc\Parameters" = "$homedrive\\Windows\\System32\\CDPUserSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc\Parameters" = "$homedrive\\Windows\\System32\\certprop\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC\Parameters" = "$homedrive\\Windows\\System32\\ClipSVC\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc\Parameters" = "$homedrive\\Windows\\system32\\cloudidsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc\Parameters" = "$homedrive\\Windows\\System32\\ConsentUxClient\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar\Parameters" = "$homedrive\\Windows\\system32\\coremessaging\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters" = "$homedrive\\Windows\\system32\\cryptsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService\Parameters" = "$homedrive\\Windows\\System32\\cscsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch\Parameters" = "$homedrive\\Windows\\system32\\rpcss\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dcsvc\Parameters" = "$homedrive\\Windows\\system32\\dcsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc\Parameters" = "$homedrive\\Windows\\System32\\defragsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc\Parameters" = "$homedrive\\Windows\\System32\\deviceaccess\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService\Parameters" = "$homedrive\\Windows\\system32\\das\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters" = "$homedrive\\Windows\\system32\\umpnpmgr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc\Parameters" = "$homedrive\\Windows\\System32\\Windows\.Devices\.Picker\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc\Parameters" = "$homedrive\\Windows\\System32\\DevicesFlowBroker\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker\Parameters" = "$homedrive\\Windows\\system32\\DevQueryBroker\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp\Parameters" = "$homedrive\\Windows\\system32\\dhcpcore\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc\Parameters" = "$homedrive\\Windows\\system32\\DiagSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" = "$homedrive\\Windows\\system32\\diagtrack\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService\Parameters" = "$homedrive\\Windows\\System32\\DialogBlockingService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc\Parameters" = "$homedrive\\Windows\\System32\\DispBroker\.Desktop\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService\Parameters" = "$homedrive\\Windows\\system32\\Microsoft\.Graphics\.Display\.DisplayEnhancementService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc\Parameters" = "$homedrive\\Windows\\system32\\Windows\.Internal\.Management\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters" = "$homedrive\\Windows\\system32\\dmwappushsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" = "$homedrive\\Windows\\System32\\dnsrslvr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc\Parameters" = "$homedrive\\Windows\\System32\\dot3svc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS\Parameters" = "$homedrive\\Windows\\system32\\dps\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc\Parameters" = "$homedrive\\Windows\\System32\\DeviceSetupManager\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc\Parameters" = "$homedrive\\Windows\\System32\\DsSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc\Parameters" = "$homedrive\\Windows\\System32\\dusmsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eaphost\Parameters" = "$homedrive\\Windows\\System32\\eapsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS\Parameters" = "$homedrive\\Windows\\system32\\efssvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters" = "$homedrive\\Windows\\System32\\embeddedmodesvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc\parameters" = "$homedrive\\Windows\\system32\\EnterpriseAppMgmtSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Parameters" = "$homedrive\\Windows\\System32\\wevtsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem\Parameters" = "$homedrive\\Windows\\system32\\es\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost\Parameters" = "$homedrive\\Windows\\system32\\fdPHost\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub\Parameters" = "$homedrive\\Windows\\system32\\fdrespub\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc\Parameters" = "$homedrive\\Windows\\system32\\fhsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache\Parameters" = "$homedrive\\Windows\\system32\\FntCache\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer\parameters" = "$homedrive\\Windows\\system32\\FrameServer\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc\Parameters" = "$homedrive\\Windows\\System32\\gpsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters" = "$homedrive\\Windows\\System32\\GraphicsPerfSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv\Parameters" = "$homedrive\\Windows\\system32\\hidserv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns\Parameters" = "$homedrive\\Windows\\System32\\HostNetSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupListener\Parameters" = "$homedrive\\Windows\\system32\\ListSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupProvider\Parameters" = "$homedrive\\Windows\\system32\\provsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost\Parameters" = "$homedrive\\Windows\\System32\\hvhostsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc\Parameters" = "$homedrive\\Windows\\System32\\tetheringservice\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT\Parameters" = "$homedrive\\Windows\\System32\\ikeext\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService\Parameters" = "$homedrive\\Windows\\system32\\InstallService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters" = "$homedrive\\Windows\\System32\\iphlpsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc\Parameters" = "$homedrive\\Windows\\System32\\IpxlatCfg\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso\Parameters" = "$homedrive\\Windows\\system32\\keyiso\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm\Parameters" = "$homedrive\\Windows\\system32\\msdtckrm\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = "$homedrive\\Windows\\system32\\srvsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = "$homedrive\\Windows\\System32\\wkssvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Parameters" = "$homedrive\\Windows\\System32\\lfsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager\Parameters" = "$homedrive\\Windows\\system32\\LicenseManagerSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc\Parameters" = "$homedrive\\Windows\\System32\\lltdsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts\Parameters" = "$homedrive\\Windows\\System32\\lmhsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM\Parameters" = "$homedrive\\Windows\\System32\\lsm\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc\Parameters" = "$homedrive\\Windows\\System32\\LanguageOverlayServer\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager\parameters" = "$homedrive\\Windows\\system32\\lxss\\LxssManager\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManagerUser\parameters" = "$homedrive\\Windows\\system32\\lxss\\wslclient\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker\Parameters" = "$homedrive\\Windows\\System32\\moshost\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService\Parameters" = "$homedrive\\Windows\\System32\\McpManagementService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService\Parameters" = "$homedrive\\Windows\\System32\\MessagingService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc\Parameters" = "$homedrive\\Windows\\System32\\MixedRealityRuntime\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc\Parameters" = "$homedrive\\Windows\\system32\\mpssvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI\Parameters" = "$homedrive\\Windows\\system32\\iscsiexe\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter\Parameters" = "$homedrive\\Windows\\System32\\KeyboardFilterSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication\Parameters" = "$homedrive\\Windows\\System32\\NaturalAuth\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc\Parameters" = "$homedrive\\Windows\\System32\\ncasvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService\Parameters" = "$homedrive\\Windows\\System32\\ncbservice\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup\Parameters" = "$homedrive\\Windows\\System32\\NcdAutoSetup\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" = "$homedrive\\Windows\\system32\\netlogon\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman\Parameters" = "$homedrive\\Windows\\System32\\netman\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm\Parameters" = "$homedrive\\Windows\\System32\\netprofmsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc\Parameters" = "$homedrive\\Windows\\System32\\NetSetupSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc\Parameters" = "$homedrive\\Windows\\System32\\NgcCtnrSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc\Parameters" = "$homedrive\\Windows\\system32\\ngcsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters" = "$homedrive\\Windows\\System32\\nlasvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi\Parameters" = "$homedrive\\Windows\\system32\\nsisvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvagent\Parameters" = "$homedrive\\Windows\\System32\\NvAgent\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc\Parameters" = "$homedrive\\Windows\\System32\\APHostService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc\Parameters" = "$homedrive\\Windows\\system32\\pnrpsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc\Parameters" = "$homedrive\\Windows\\system32\\p2psvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc\Parameters" = "$homedrive\\Windows\\System32\\pcasvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc\parameters" = "$homedrive\\Windows\\system32\\peerdistsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc\Parameters" = "$homedrive\\Windows\\System32\\PhoneService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc\Parameters" = "$homedrive\\Windows\\System32\\PimIndexMaintenance\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla\Parameters" = "$homedrive\\Windows\\system32\\pla\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay\Parameters" = "$homedrive\\Windows\\system32\\umpnpmgr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg\parameters" = "$homedrive\\Windows\\system32\\pnrpauto\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc\parameters" = "$homedrive\\Windows\\system32\\pnrpsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent\Parameters" = "$homedrive\\Windows\\System32\\ipsecsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power\Parameters" = "$homedrive\\Windows\\system32\\umpo\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify\Parameters" = "$homedrive\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc\Parameters" = "$homedrive\\Windows\\System32\\PrintWorkflowService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc\Parameters" = "$homedrive\\Windows\\system32\\profsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall\Parameters" = "$homedrive\\Windows\\system32\\PushToInstall\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE\Parameters" = "$homedrive\\Windows\\system32\\qwave\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto\Parameters" = "$homedrive\\Windows\\System32\\rasauto\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" = "$homedrive\\Windows\\System32\\rasmans\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters" = "$homedrive\\Windows\\System32\\mprdim\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry\Parameters" = "$homedrive\\Windows\\system32\\regsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo\Parameters" = "$homedrive\\Windows\\system32\\RDXService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc\Parameters" = "$homedrive\\Windows\\System32\\RMapi\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper\Parameters" = "$homedrive\\Windows\\System32\\RpcEpMap\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs\Parameters" = "$homedrive\\Windows\\system32\\rpcss\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr\Parameters" = "$homedrive\\Windows\\System32\\SCardSvr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum\Parameters" = "$homedrive\\Windows\\System32\\ScDeviceEnum\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule\Parameters" = "$homedrive\\Windows\\system32\\schedsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc\Parameters" = "$homedrive\\Windows\\System32\\certprop\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC\Parameters" = "$homedrive\\Windows\\System32\\SDRSVC\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon\Parameters" = "$homedrive\\Windows\\system32\\seclogon\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc\Parameters" = "$homedrive\\Windows\\system32\\SEMgrSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS\Parameters" = "$homedrive\\Windows\\System32\\sens\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService\Parameters" = "$homedrive\\Windows\\system32\\SensorService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc\Parameters" = "$homedrive\\Windows\\system32\\sensrsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv\Parameters" = "$homedrive\\Windows\\system32\\sessenv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters" = "$homedrive\\Windows\\System32\\ipnathlp\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc\Parameters" = "$homedrive\\Windows\\System32\\SharedRealitySvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection\Parameters" = "$homedrive\\Windows\\System32\\shsvcs\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc\Parameters" = "$homedrive\\Windows\\system32\\Windows\.SharedPC\.AccountManager\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost\Parameters" = "$homedrive\\Windows\\System32\\smphost\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter\Parameters" = "$homedrive\\Windows\\system32\\SmsRouterSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV\Parameters" = "$homedrive\\Windows\\System32\\ssdpsrv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc\Parameters" = "$homedrive\\Windows\\system32\\sstpsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository\parameters" = "$homedrive\\Windows\\system32\\windows\.staterepository\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc\Parameters" = "$homedrive\\Windows\\System32\\wiaservc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc\Parameters" = "$homedrive\\Windows\\system32\\storsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc\Parameters" = "$homedrive\\Windows\\system32\\svsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv\Parameters" = "$homedrive\\Windows\\System32\\swprv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain\Parameters" = "$homedrive\\Windows\\system32\\sysmain\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker\Parameters" = "$homedrive\\Windows\\System32\\SystemEventsBrokerServer\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService\Parameters" = "$homedrive\\Windows\\System32\\TabSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv\Parameters" = "$homedrive\\Windows\\System32\\tapisrv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters" = "$homedrive\\Windows\\System32\\termsrv\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes\Parameters" = "$homedrive\\Windows\\system32\\themeservice\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc\Parameters" = "$homedrive\\Windows\\System32\\TimeBrokerServer\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker\Parameters" = "$homedrive\\Windows\\System32\\TokenBroker\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks\Parameters" = "$homedrive\\Windows\\System32\\trkwks\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc\Parameters" = "$homedrive\\Windows\\system32\\MitigationClient\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate\Parameters" = "$homedrive\\Windows\\system32\\tzautoupdate\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc\Parameters" = "$homedrive\\Windows\\System32\\windowsudk\.shellcommon\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService\Parameters" = "$homedrive\\Windows\\System32\\umrdp\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc\Parameters" = "$homedrive\\Windows\\System32\\unistore\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost\Parameters" = "$homedrive\\Windows\\System32\\upnphost\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc\Parameters" = "$homedrive\\Windows\\System32\\userdataservice\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager\Parameters" = "$homedrive\\Windows\\System32\\usermgr\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc\Parameters" = "$homedrive\\Windows\\system32\\usosvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc\Parameters" = "$homedrive\\Windows\\System32\\vac\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc\Parameters" = "$homedrive\\Windows\\System32\\vaultsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv\Parameters" = "$homedrive\\Windows\\System32\\icsvcext\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession\Parameters" = "$homedrive\\Windows\\System32\\icsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss\Parameters" = "$homedrive\\Windows\\System32\\icsvcext\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" = "$homedrive\\Windows\\system32\\w32time\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\Parameters" = "$homedrive\\Windows\\System32\\WaaSMedicSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService\Parameters" = "$homedrive\\Windows\\system32\\WalletService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc\Parameters" = "$homedrive\\Windows\\System32\\Windows\.WARP\.JITService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Parameters" = "$homedrive\\Windows\\System32\\wbiosrvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc\Parameters" = "$homedrive\\Windows\\System32\\wcmsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc\Parameters" = "$homedrive\\Windows\\System32\\wcncsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost\Parameters" = "$homedrive\\Windows\\system32\\wdi\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost\Parameters" = "$homedrive\\Windows\\system32\\wdi\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters" = "$homedrive\\Windows\\System32\\webclnt\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc\Parameters" = "$homedrive\\Windows\\system32\\wecsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC\Parameters" = "$homedrive\\Windows\\system32\\wephostsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport\Parameters" = "$homedrive\\Windows\\System32\\wercplsupport\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc\Parameters" = "$homedrive\\Windows\\System32\\WerSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc\Parameters" = "$homedrive\\Windows\\System32\\wfdsconmgrsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc\Parameters" = "$homedrive\\Windows\\System32\\wiarpc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc\Parameters" = "$homedrive\\Windows\\system32\\winhttp\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt\Parameters" = "$homedrive\\Windows\\system32\\wbem\\WMIsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM\Parameters" = "$homedrive\\Windows\\system32\\WsmSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc\Parameters" = "$homedrive\\Windows\\system32\\flightsettings\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters" = "$homedrive\\Windows\\System32\\wlansvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc\Parameters" = "$homedrive\\Windows\\system32\\wlidsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc\Parameters" = "$homedrive\\Windows\\System32\\lpasvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc\Parameters" = "$homedrive\\Windows\\system32\\Windows\.Management\.Service\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc\Parameters" = "$homedrive\\Windows\\system32\\workfolderssvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc\Parameters" = "$homedrive\\Windows\\System32\\WpcDesktopMonSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum\Parameters" = "$homedrive\\Windows\\system32\\wpdbusenum\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService\parameters" = "$homedrive\\Windows\\system32\\WpnService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService\Parameters" = "$homedrive\\Windows\\System32\\WpnUserService\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc\Parameters" = "$homedrive\\Windows\\System32\\wscsvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv\Parameters" = "$homedrive\\Windows\\system32\\wuaueng\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc\Parameters" = "$homedrive\\Windows\\System32\\wwansvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager\Parameters" = "$homedrive\\Windows\\System32\\XblAuthManager\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave\Parameters" = "$homedrive\\Windows\\System32\\XblGameSave\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc\Parameters" = "$homedrive\\Windows\\System32\\XboxGipSvc\.dll"
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\Parameters" = "$homedrive\\Windows\\system32\\XboxNetApiSvc\.dll"
    }

    if (Test-Path -Path "Registry::$path") {
        $services = Get-ChildItem -Path "Registry::$path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($service in $services) {
            $service_path = "Registry::"+$service.Name
            $service_children_keys = Get-ChildItem -Path "$service_path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $service_data = Get-ItemProperty -Path $service_path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            $service_data.PSObject.Properties | ForEach-Object {
                if ($_.Name -eq 'ImagePath'){
                    if ($image_path_lookup.ContainsKey($service.Name)){
                        if ($_.Value -notmatch $image_path_lookup[$service.Name]){
                                $detection = [PSCustomObject]@{
                                    Name = 'Possible Service Hijack - Unexpected ImagePath Location'
                                    Risk = 'Medium'
                                    Source = 'Services'
                                    Technique = "T1543.003: Create or Modify System Process: Windows Service"
                                    Meta = "Key: " + $service.Name + ", Value: " + $_.Value+" Regex Expected Locastion: "+$service_dll_lookup[$child_key.Name]
                                }
                                Write-Detection $detection
                        }
                    } elseif (1 -eq 1){
                    }
                }
            }
            ForEach ($child_key in $service_children_keys) {
                #Write-Host $child_key.Name
                $child_path = "Registry::"+$child_key.Name
                $data = Get-ItemProperty -Path $child_path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
                $data.PSObject.Properties | ForEach-Object {
                    if ($_.Name -eq "ServiceDll"){
                        if ($service_dll_lookup.ContainsKey($child_key.Name)){
                            if ($_.Value -notmatch $service_dll_lookup[$child_key.Name]){
                                #Write-Host "NAME:"$child_key.Name
                                #Write-Host "DETECTION: "$_.Value", Original: "$service_dll_lookup[$child_key.Name]
                                $detection = [PSCustomObject]@{
                                    Name = 'Possible Service Hijack - Unexpected ServiceDll Location'
                                    Risk = 'Medium'
                                    Source = 'Services'
                                    Technique = "T1543.003: Create or Modify System Process: Windows Service"
                                    Meta = "Key: " + $child_key.Name + ", Value: " + $_.Value+" Regex Expected Locastion: "+$service_dll_lookup[$child_key.Name]
                                }
                                Write-Detection $detection
                            }
                        } elseif (1 -eq 1){
                        }
                    }
                }
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
                        Source = 'LNK'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = "LNK File: "+$item.FullName+", LNK Target: "+$lnk_target+", Last Write Time: "+$item.LastWriteTime
                    }
                    Write-Detection $detection
                }
                if ($lnk_target -match $suspicious_terms){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains suspicious key-term'
                        Risk = 'High'
                        Source = 'LNK'
                        Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
                        Meta = "LNK File: "+$item.FullName+", LNK Target: "+$lnk_target+", Last Write Time: "+$item.LastWriteTime
                    }
                    Write-Detection $detection
                }
                if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*"){
                    $detection = [PSCustomObject]@{
                        Name = 'LNK Target contains multiple file extensions'
                        Risk = 'Medium'
                        Source = 'LNK'
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
                            Source = 'Processes'
                            Technique = "T1574: Hijack Execution Flow"
                            Meta = "DLL: "+$module.FileName+", Process Name: "+$process.ProcessName+", PID: "+$process.ProcessId+", Execuable Path: "+$process.ExecutablePath+", DLL Creation Time: "+$item.CreationTime+", DLL Last Write Time: "+$item.LastWriteTime
                        }
                        Write-Detection $detection
                    } else {
                        $item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
                        $detection = [PSCustomObject]@{
                            Name = 'Suspicious DLL with commonly-masqueraded name loaded into running process.'
                            Risk = 'High'
                            Source = 'Processes'
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

function Find-Service-Hijacks {
    $services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
    ForEach ($service in $services){
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
                ForEach ($path in $tmp_path){
                    $base_path += $path
                    $test_path = $base_path + ".exe"
                    if (Test-Path $test_path) {
                        $detection = [PSCustomObject]@{
                            Name = 'Possible Service Path Hijack via Unquoted Path'
                            Risk = 'High'
                            Source = 'Services'
                            Technique = "T1574.009: Create or Modify System Process: Windows Service"
                            Meta = "Service Name: "+ $service.Name+", Service Path: "+ $service.PathName+", Suspicious File: "+$test_path
                        }
                        Write-Detection $detection
                    }
                    $base_path += " "
                }
            }
        }
    }
}

function Find-PATH-Hijacks {
    $system32_path = $env:windir+'\system32'
    $system32_bins = Get-ChildItem -File -Path $system32_path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object Name
    $sys32_bins = New-Object -TypeName "System.Collections.ArrayList"

    ForEach ($bin in $system32_bins){
        $sys32_bins.Add($bin.Name) | Out-Null
    }

    $path_entries = $env:PATH.Split(";")
    $paths_before_sys32 = New-Object -TypeName "System.Collections.ArrayList"
    ForEach ($path in $path_entries){
        if ($path -ne $system32_path){
            $paths_before_sys32.Add($path) | Out-Null
        } else {
            break
        }
    }

    ForEach ($path in $paths_before_sys32){
        $path_bins = Get-ChildItem -File -Path $path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object *
        ForEach ($bin in $path_bins){
            if ($bin.Name -in $sys32_bins){
                $detection = [PSCustomObject]@{
                    Name = 'Possible PATH Binary Hijack - same name as SYS32 binary'
                    Risk = 'Very High'
                    Source = 'PATH'
                    Technique = "T1574.007: Hijack Execution Flow: Path Interception by PATH Environment Variable"
                    Meta = "File: " + $bin.FullName + ", Creation Time: " + $bin.CreationTime + ", Last Write Time: " + $bin.LastWriteTime
                }
                #Write-Host $detection.Meta
                Write-Detection $detection
            }
        }

    }
}

function File-Association-Hijack {

    $homedrive = $env:HOMEDRIVE
    $value_regex_lookup = @{
        accesshtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\MSACCESS.EXE`"";
        batfile = '"%1" %';
        certificate_wab_auto_file = "`"$homedrive\\Program Files\\Windows Mail\\wab.exe`" /certificate `"%1`"";
        "chm.file" = "`"$homedrive\\Windows\\hh.exe`" %1"
        cmdfile = '"%1" %';
        comfile = '"%1" %';
        desktopthemepackfile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1";
        evtfile = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
        evtxfile = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
        exefile = '"%1" %\*';
        hlpfile = "$homedrive\\Windows\\winhlp32.exe %1";
        mscfile = "$homedrive\\Windows\\system32\\mmc.exe `"%1`" %\*";
        powerpointhtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
        powerpointxmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
        prffile = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnPRF %1";
        ratfile = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnRAT %1";
        regfile = "regedit.exe `"%1`""
        scrfile = "`"%1`" /S"
        themefile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
        themepackfile = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
        wbcatfile = "$homedrive\\Windows\\system32\\sdclt.exe /restorepage"
        wcxfile = "`"$homedrive\\Windows\\System32\\xwizard.exe`" RunWizard /u {.*} /z%1"
        "wireshark-capture-file" = "`"$homedrive\\.*\\Wireshark.exe`" `"%1`""
        wordhtmlfile = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\WINWORD.EXE`""

    }

    if (Test-Path -Path "Registry::HKEY_CLASSES_ROOT") {
        $items = Get-ChildItem -Path "Registry::HKEY_CLASSES_ROOT" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        ForEach ($item in $items) {
            $path = $item.Name
            if ($path.EndsWith('file')){
                $basefile = $path.Split("\")[1]
                $open_path = $path+"\shell\open\command"
                if (Test-Path -Path "Registry::$open_path"){
                    $key = Get-ItemProperty -Path "Registry::$open_path" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
                    $key.PSObject.Properties | ForEach-Object {
                        if ($_.Name -eq '(default)'){
                            #Write-Host $open_path $_.Value
                            $exe = $_.Value
                            $detection_triggered = $false

                            if ($value_regex_lookup.ContainsKey($basefile)){
                                if ($exe -notmatch $value_regex_lookup[$basefile]){
                                    $detection = [PSCustomObject]@{
                                        Name = 'Possible File Association Hijack - Mismatch on Expected Value'
                                        Risk = 'High'
                                        Source = 'Registry'
                                        Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                        Meta = "FileType: " + $basefile +", Expected Association: "+ $value_regex_lookup[$basefile] + ", Current Association: " + $exe
                                    }
                                    Write-Detection $detection
                                    return
                                } else {
                                    return
                                }
                            }

                            if ($exe -match ".*\.exe.*\.exe"){
                                $detection = [PSCustomObject]@{
                                    Name = 'Possible File Association Hijack - Multiple EXEs'
                                    Risk = 'High'
                                    Source = 'Registry'
                                    Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                    Meta = "FileType: " + $basefile + ", Current Association: " + $exe
                                }
                                Write-Detection $detection
                                return
                            }
                            if ($exe -match $suspicious_terms){
                                $detection = [PSCustomObject]@{
                                    Name = 'Possible File Association Hijack - Suspicious Keywords'
                                    Risk = 'High'
                                    Source = 'Registry'
                                    Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                    Meta = "FileType: " + $basefile + ", Current Association: " + $exe
                                }
                                Write-Detection $detection
                            }
                        }
                    }
                }
            }
        }
    }
}

function Find-Suspicious-Certificates {
    $certs = Get-ChildItem -path cert:\ -Recurse | Select-Object *
    # PSPath,DnsNameList,SendAsTrustedIssuer,PolicyId,Archived,FriendlyName,IssuerName,NotAfter,NotBefore,HasPrivateKey,SerialNumber,SubjectName,Version,Issuer,Subject
    $wellknown_ca = @(
        "DigiCert.*",
        "GlobalSign.*",
        "Comodo.*",
        "VeriSign.*",
        "Microsoft Corporation.*",
        "Go Daddy.*"
        "SecureTrust.*"
        "Entrust.*"
        "Microsoft.*"
        "USERTrust RSA Certification Authority"
        "Blizzard.*"
        "Hellenic Academic and Research Institutions.*"
        "Starfield.*"
        "T-TeleSec GlobalRoot.*"
        "QuoVadis.*"
        "ISRG Root.*"
        "Baltimore CyberTrust.*"
        "Security Communication Root.*"
        "AAA Certificate Services.*"
        "thawte Primary Root.*"
        "SECOM Trust.*"
        "Certum Trusted Network.*"
        "SSL\.com Root Certification.*"

    )
    $date = Get-Date
    ForEach ($cert in $certs){
        # Skip current object if it is a container of a cert rather than a certificate directly
        if ($cert.PSIsContainer){
            continue
        }
        if ($cert.PSPath.Contains("\Root\") -or $cert.PSPath.Contains("\AuthRoot\") -or $cert.PSPath.Contains("\CertificateAuthority\")){
            $trusted_cert = $true
        } else {
            continue
        }

        $cn_pattern = ".*CN=(.*?),.*"
        $cn_pattern_2 = "CN=(.*)"
        $ou_pattern = ".*O=(.*?),.*"
        $ou_pattern_2 = ".*O=(.*?)"

        $cn_match = [regex]::Matches($cert.Issuer, $cn_pattern).Groups.Captures.Value
        #Write-Host $cert.Issuer
        if ($cn_match -ne $null){
            #Write-Host $cn_match[1]
        } else {
            $cn_match = [regex]::Matches($cert.Issuer, $cn_pattern_2).Groups.Captures.Value
            if ($cn_match -ne $null){
                #Write-Host $cn_match[1]
            } else {
                $cn_match = [regex]::Matches($cert.Issuer, $ou_pattern).Groups.Captures.Value
                #Write-Host $cn_match[1]
                if ($cn_match -eq $null){
                $cn_match = [regex]::Matches($cert.Issuer, $ou_pattern_2).Groups.Captures.Value
                }
            }
        }

        $signer = $cn_match[1]
        $diff = New-TimeSpan -Start $date -End $cert.NotAfter
        $cert_verification_status = Test-Certificate -Cert $cert.PSPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        ForEach ($ca in $wellknown_ca){
            if ($signer -match $ca){
                #Write-Host "Comparing:"+$signer+" to"+$ca
                $valid_signer = $true
                break
            } else {
                $valid_signer = $false
            }
        }

        # Valid Cert, Unknown Signer, Valid in Date, Contains Root/AuthRoot/CertificateAuthority
        if ($cert_verification_status -eq $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
            $detection = [PSCustomObject]@{
                Name = 'Valid Root or CA Certificate Issued by Non-Standard Authority'
                Risk = 'Low'
                Source = 'Certificates'
                Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
                Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
            }
            Write-Detection $detection
            #Write-Host $detection.Meta
        }
        if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
            $detection = [PSCustomObject]@{
                Name = 'Invalid Root or CA Certificate Issued by Non-Standard Authority'
                Risk = 'Low'
                Source = 'Certificates'
                Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
                Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
            }
            Write-Detection $detection
            #Write-Host $detection.Meta
        }


        #$cert.SubjectName.Name
        if ($cert_verification_status -ne $true -and $diff.Hours -ge 0){
            # Invalid Certs that are still within valid range
            if ($cert.PSPath.Contains("\Root\")){
                $detection = [PSCustomObject]@{
                    Name = 'Installed Trusted Root Certificate Failed Validation'
                    Risk = 'Medium'
                    Source = 'Certificates'
                    Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
                    Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
                }
                Write-Detection $detection
                #Write-Host $detection.Meta
            } elseif ($cert.PSPath.Contains("\AuthRoot\")){
                $detection = [PSCustomObject]@{
                    Name = 'Installed Third-Party Root Certificate Failed Validation'
                    Risk = 'Low'
                    Source = 'Certificates'
                    Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
                    Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
                }
                Write-Detection $detection
                #Write-Host $detection.Meta
            } elseif ($cert.PSPath.Contains("\CertificateAuthority\")){
                $detection = [PSCustomObject]@{
                    Name = 'Installed Intermediary Certificate Failed Validation'
                    Risk = 'Low'
                    Source = 'Certificates'
                    Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
                    Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
                }
                Write-Detection $detection
                #Write-Host $detection.Meta
            } else {
                $detection = [PSCustomObject]@{
                    Name = 'Installed Certificate Failed Validation'
                    Risk = 'Very Low'
                    Source = 'Certificates'
                    Technique = "T1553: Subvert Trust Controls"
                    Meta = "Subject Name: "+$cert.SubjectName.Name+", Friendly Name: "+$cert.FriendlyName+", Issuer: "+$cert.Issuer+", Subject: "+$cert.Subject+", NotValidAfter: "+$cert.NotAfter+", NotValidBefore: "+$cert.NotBefore
                }
                Write-Detection $detection
                #Write-Host $detection.Meta
            }
        } elseif ($cert_verification_status -and $diff.Hours -ge 0){
            # Validated Certs that are still valid
        }
    }
}

function Scan-Office-Trusted-Locations {
    $profile_names = Get-ChildItem 'C:\Users' -Attributes Directory | Select-Object *
    $current_user = $env:USERNAME

    if (Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations") {
        $items = Get-ChildItem -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations" | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $possible_paths = New-Object -TypeName "System.Collections.ArrayList"
        ForEach ($item in $items) {
            $path = "Registry::"+$item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
            if ($data.Path -ne $null){
                $possible_paths.Add($data.Path) | Out-Null
                if ($data.Path.Contains($current_user)){
                    ForEach ($user in $profile_names){
                        $new_path = $data.Path.replace($current_user, $user.Name)
                        if ($possible_paths -notcontains $new_path) {
                            $possible_paths.Add($new_path) | Out-Null
                        }
                    }
                }
            }
        }
    }

    ForEach ($p in $possible_paths){
        if (Test-Path $p){
            $items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object {$_.extension -in $office_addin_extensions}
            ForEach ($item in $items){
                $detection = [PSCustomObject]@{
                    Name = 'Potential Persistence via Office Startup Addin'
                    Risk = 'Medium'
                    Source = 'Office'
                    Technique = "T1137.006: Office Application Startup: Add-ins"
                    Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
                }
                Write-Detection $detection
            }
        }
    }
}


function Find-GPO-Scripts {
    $base_key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts"
    $script_paths = New-Object -TypeName "System.Collections.ArrayList"
    $homedrive = $env:HOMEDRIVE
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

    ForEach ($path in $paths){
        # Skip non-existent files
        if((Test-Path $path) -eq $false){
            return
        }
        $content = Get-Content $path
        $script_type = ""
        ForEach ($line in $content){
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
                $script_content_detection = $false
                try {
                    $script_content = Get-Content $script_location
                    ForEach ($line_ in $script_content){
                        if ($line_ -match $suspicious_terms -and $script_content_detection -eq $false){
                            $detection = [PSCustomObject]@{
                                Name = 'Suspicious Content in '+$desc
                                Risk = 'High'
                                Source = 'Windows GPO Scripts'
                                Technique = "T1037: Boot or Logon Initialization Scripts"
                                Meta = "File: "+$script_location+", Arguments: "+$params+", Suspicious Line: "+$line_
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
                        Meta = "File: "+$script_location+", Arguments: "+$params
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
    $profile_names = Get-ChildItem 'C:\Users' -Attributes Directory | Select-Object *
    $base_path = "$env:homedrive\Users\_USER_\AppData\Local\Packages\"
    ForEach ($user in $profile_names){
        $new_path = $base_path.replace("_USER_", $user.Name)
        $new_path += "Microsoft.WindowsTerminal*"
        $terminalDirs = Get-ChildItem $new_path -ErrorAction SilentlyContinue
        ForEach ($dir in $terminalDirs){
            if (Test-Path "$dir\LocalState\settings.json"){
                $settings_data = Get-Content -Raw "$dir\LocalState\settings.json" | ConvertFrom-Json
                if ($settings_data.startOnUserLogin -eq $null -or $settings_data.startOnUserLogin -ne $true){
                    continue
                }
                $defaultGUID = $settings_data.defaultProfile
                ForEach ($profile_list in $settings_data.profiles){
                    ForEach ($profile in $profile_list.List){
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
                                Meta = "File: $dir\LocalState\settings.json, Command: "+$exe
                            }
                            Write-Detection $detection
                        }
                    }
                }
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
    } else {
        $fg_color = 'Yellow'
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
    Find-Service-Hijacks
    Find-PATH-Hijacks
    File-Association-Hijack
    Find-Suspicious-Certificates
    Scan-Office-Trusted-Locations
    Find-GPO-Scripts
    Check-TerminalProfiles
}

Main