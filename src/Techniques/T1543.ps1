
function Search-Services {
	# Supports Dynamic Snapshotting
	# Support Drive Retargeting
	Write-Message "Checking Windows Services"
	$default_service_exe_paths = @(
		"`"$env_assumedhomedrive\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /medsvc",
		"`"$env_assumedhomedrive\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /svc",
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\Edge\Application\*\elevation_service.exe`"",
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /medsvc",
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /svc",
		"`"$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe`" /service",
		"`"$env_assumedhomedrive\Program Files\Google\Chrome\Application\*\elevation_service.exe`"",
		"`"$env_assumedhomedrive\Program Files\Microsoft OneDrive\*\FileSyncHelper.exe`"",
		"`"$env_assumedhomedrive\Program Files\Microsoft OneDrive\*\OneDriveUpdaterService.exe`"",
		"`"$env_assumedhomedrive\Program Files\Microsoft Update Health Tools\uhssvc.exe`"",
		"`"$env_assumedhomedrive\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe`" -s NVDisplay.ContainerLocalSystem -f `"$env_assumedhomedrive\ProgramData\NVIDIA\NVDisplay.ContainerLocalSystem.log`" -l 3 -d `"$env_assumedhomedrive\Program Files\NVIDIA Corporation\Display.NvContainer\plugins\LocalSystem`" -r -p 30000 ",
		"`"$env_assumedhomedrive\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe`"",
		"`"$env_assumedhomedrive\Program Files\Windows Media Player\wmpnetwk.exe`"",
		"`"$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`"",
		"`"$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe`"",
		"`"$env_assumedhomedrive\Windows\CxSvc\CxAudioSvc.exe`"",
		"`"$env_assumedhomedrive\Windows\CxSvc\CxUtilSvc.exe`"",
		"`"$env_assumedhomedrive\Windows\System32\wbengine.exe`"",
		"$env_assumedhomedrive\Windows\Microsoft.Net\*\*\WPF\PresentationFontCache.exe",
		"$env_assumedhomedrive\Windows\Microsoft.NET\Framework64\*\SMSvcHost.exe",
		"$env_assumedhomedrive\Windows\servicing\TrustedInstaller.exe",
		"$env_assumedhomedrive\Windows\System32\AgentService.exe",
		"$env_assumedhomedrive\Windows\System32\alg.exe",
		"$env_assumedhomedrive\Windows\System32\Alps\GlidePoint\HidMonitorSvc.exe",
		"$env_assumedhomedrive\Windows\System32\AppVClient.exe",
		"$env_assumedhomedrive\Windows\System32\cAVS\Intel(R) Audio Service\IntelAudioService.exe",
		"$env_assumedhomedrive\Windows\System32\CredentialEnrollmentManager.exe",
		"$env_assumedhomedrive\Windows\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_*\igfxCUIService.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\HotKeyServiceUWP.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\LanWlanWwanSwitchingServiceUWP.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\iaahcic.inf_amd64_*\RstMwService.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\igcc_dch.inf_amd64_*\OneApp.IGCC.WinService.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHDCPSvc.exe",
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHeciSvc.exe",
		"$env_assumedhomedrive\Windows\System32\fxssvc.exe",
		"$env_assumedhomedrive\Windows\System32\ibtsiva",
		"$env_assumedhomedrive\Windows\System32\locator.exe",
		"$env_assumedhomedrive\Windows\System32\lsass.exe",
		"$env_assumedhomedrive\Windows\System32\msdtc.exe",
		"$env_assumedhomedrive\Windows\System32\msiexec.exe /V",
		"$env_assumedhomedrive\Windows\System32\nvwmi64.exe",
		"$env_assumedhomedrive\Windows\System32\OpenSSH\ssh-agent.exe",
		"$env_assumedhomedrive\Windows\System32\PerceptionSimulation\PerceptionSimulationService.exe",
		"$env_assumedhomedrive\Windows\System32\RSoPProv.exe",
		"$env_assumedhomedrive\WINDOWS\RtkBtManServ.exe",
		"$env_assumedhomedrive\Windows\runSW.exe",
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k rpcss"
		"$env_assumedhomedrive\Windows\System32\SearchIndexer.exe /Embedding",
		"$env_assumedhomedrive\Windows\System32\SecurityHealthService.exe",
		"$env_assumedhomedrive\Windows\System32\SensorDataService.exe",
		"$env_assumedhomedrive\Windows\System32\SgrmBroker.exe",
		"$env_assumedhomedrive\Windows\System32\snmptrap.exe",
		"$env_assumedhomedrive\Windows\System32\spectrum.exe",
		"$env_assumedhomedrive\Windows\System32\spoolsv.exe",
		"$env_assumedhomedrive\Windows\System32\sppsvc.exe",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AarSvcGroup -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k appmodel -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k appmodel",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AppReadiness -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AppReadiness",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AssignedAccessManagerSvc",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k autoTimeSvc",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AxInstSVGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k BcastDVRUserService",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k BthAppGroup -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k Camera",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k CameraMonitor",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k ClipboardSvcGroup -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k CloudIdServiceGroup -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k DcomLaunch -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k DcomLaunch",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k defragsvc",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k DevicesFlow -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k DevicesFlow",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k diagnostics",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k DialogBlockingService",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k ICService -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k imgsvc",
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k ICService",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k KpsSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k localService -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetwork",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetworkFirewall -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServicePeerNet",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted",
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k McpManagementServiceGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetSvcs -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k PeerDist",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k print",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k PrintWorkflow",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k rdxgroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k rpcss -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k RPCSS -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k SDRSVC",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k smbsvcs",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k smphost",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k swprv",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k termsvcs",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k UdkSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k UnistackSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k utcsvc -p",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k utcsvc",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k WbioSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k WepHostSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k WerSvcGroup",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k wsappx -p",
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k wcssvc"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k wsappx",
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k wusvcs -p",
		"$env_assumedhomedrive\Windows\System32\TieringEngineService.exe",
		"$env_assumedhomedrive\Windows\System32\UI0Detect.exe",
		"$env_assumedhomedrive\Windows\System32\vds.exe",
		"$env_assumedhomedrive\Windows\System32\vssvc.exe",
		"$env_assumedhomedrive\Windows\System32\wbem\WmiApSrv.exe",
		"$env_assumedhomedrive\Windows\SysWow64\perfhost.exe",
		"$env_assumedhomedrive\Windows\SysWOW64\XtuService.exe"
		"$env_assumedhomedrive\WINDOWS\system32\dllhost.exe /Processid:*"
		"$env_assumedhomedrive\Windows\System32\drivers\1394ohci.sys"
		"System32\drivers\3ware.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k AarSvcGroup -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k AarSvcGroup -p"
		"System32\drivers\ACPI.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\AcpiDev.sys"
		"System32\Drivers\acpiex.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\acpipagr.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\acpipmi.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\acpitime.sys"
		"system32\drivers\Acx01000.sys"
		"System32\drivers\ADP80XX.SYS"
		"$env_assumedhomedrive\Windows\system32\drivers\afd.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\afunix.sys"
		"system32\DRIVERS\ahcache.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\alg.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\amdgpio2.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\amdi2c.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\amdk8.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\amdppm.sys"
		"System32\drivers\amdsata.sys"
		"System32\drivers\amdsbs.sys"
		"System32\drivers\amdxata.sys"
		"system32\drivers\appid.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\AppleKmdfFilter.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\AppleLowerFilter.sys"
		"system32\drivers\applockerfltr.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k AppReadiness -p"
		"$env_assumedhomedrive\Windows\system32\AppVClient.exe"
		"$env_assumedhomedrive\Windows\system32\drivers\AppvStrm.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\AppvVemgr.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\AppvVfs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k wsappx -p"
		"System32\drivers\arcsas.sys"
		#"`"$env_assumedhomedrive\Program Files\ASUS\ARMOURY CRATE Lite Service\ArmouryCrate.Service.exe`""
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\AXSP\*\atkexComSvc.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k AssignedAccessManagerSvc"
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\Update\AsusUpdate.exe`" /svc"
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe`""
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\AsusFanControlService\*\AsusFanControlService.exe`""
		"\??\$env_assumedhomedrive\Windows\system32\drivers\AsIO2.sys"
		"\??\$env_assumedhomedrive\Windows\system32\drivers\AsIO3.sys"
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\Update\AsusUpdate.exe`" /medsvc"
		#"$env_assumedhomedrive\Windows\System32\AsusUpdateCheck.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\asyncmac.sys"
		"System32\drivers\atapi.sys"
		#"\??\D:\SteamLibrary\steamapps\common\Call of Duty HQ\randgrid.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k autoTimeSvc"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k AxInstSVGroup"
		"System32\drivers\bxvbda.sys"
		"system32\drivers\bam.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_*\BasicDisplay.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_*\BasicRender.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k BcastDVRUserService"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k BcastDVRUserService"
		"$env_assumedhomedrive\Windows\System32\drivers\bcmfn2.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		#"`"$env_assumedhomedrive\Program Files (x86)\Common Files\BattlEye\BEService.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p"
		"$env_assumedhomedrive\Windows\system32\drivers\bindflt.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k BthAppGroup -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k BthAppGroup -p"
		"system32\DRIVERS\bowser.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted"
		"$env_assumedhomedrive\Windows\System32\drivers\BthA2dp.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\drivers\BthEnum.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\bthhfenum.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\BTHMINI.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\bthmodem.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\bthpan.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\BTHport.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\drivers\BTHUSB.sys"
		"System32\drivers\bttflt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\buttonconverter.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\CAD.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k appmodel -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k ClipboardSvcGroup -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k ClipboardSvcGroup -p"
		"system32\DRIVERS\cdfs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\System32\drivers\cdrom.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs"
		"System32\drivers\cht4sx64.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\cht4vx64.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\circlass.sys"
		"system32\drivers\cldflt.sys"
		"System32\drivers\CLFS.sys"
		"`"$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe`" /service"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k wsappx -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k CloudIdServiceGroup -p"
		"$env_assumedhomedrive\Windows\System32\drivers\CmBatt.sys"
		"System32\Drivers\cng.sys"
		"System32\DRIVERS\cnghwassist.sys"
		#"`"$env_assumedhomedrive\Program Files\Docker\Docker\com.docker.service`""
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\compositebus.inf_amd64_*\CompositeBus.sys"
		"$env_assumedhomedrive\Windows\system32\dllhost.exe /Processid:{*}"
		"System32\drivers\condrv.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p"
		#"$env_assumedhomedrive\Windows\System32\CorsairGamingAudioCfgService64.exe"
		#"\??\$env_assumedhomedrive\Windows\System32\drivers\CorsairGamingAudio64.sys"
		#"\??\$env_assumedhomedrive\Program Files\Corsair\CORSAIR iCUE 4 Software\CorsairLLAccess64.sys"
		#"`"$env_assumedhomedrive\Program Files\Corsair\CORSAIR iCUE 4 Software\CueLLAccessService.exe`""
		#"`"$env_assumedhomedrive\Program Files\Corsair\CORSAIR iCUE 4 Software\Corsair.Service.exe`""
		#"`"$env_assumedhomedrive\Program Files\Corsair\CORSAIR iCUE 4 Software\CueUniwillService.exe`""
		#"$env_assumedhomedrive\Windows\System32\drivers\CorsairVBusDriver.sys"
		#"$env_assumedhomedrive\Windows\System32\drivers\CorsairVHidDriver.sys"
		#"\??\$env_assumedhomedrive\Windows\temp\cpuz152\cpuz152_x64.sys"
		#"\??\$env_assumedhomedrive\Windows\temp\cpuz153\cpuz153_x64.sys"
		#"\??\$env_assumedhomedrive\Windows\temp\cpuz154\cpuz154_x64.sys"
		"$env_assumedhomedrive\Windows\system32\CredentialEnrollmentManager.exe"
		"$env_assumedhomedrive\Windows\system32\CredentialEnrollmentManager.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetworkService -p"
		"system32\drivers\csc.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"\??\$env_assumedhomedrive\Windows\system32\drivers\CtiAIo64.sys"
		"system32\drivers\dam.sys"
		#"`"$env_assumedhomedrive\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe`" /svc"
		#"`"$env_assumedhomedrive\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe`" /medsvc"
		"$env_assumedhomedrive\Windows\system32\DbxSvc.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\dc1-controller.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k defragsvc"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DevicesFlow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\Drivers\dfsc.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k diagnostics"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k utcsvc -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DialogBlockingService"
		"System32\drivers\disk.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\dmvsc.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		"$env_assumedhomedrive\Windows\System32\drivers\drmkaud.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\dxgkrnl.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\e2f68.inf_amd64_*\e2f68.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		#"`"$env_assumedhomedrive\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.exe`""
		#"`"$env_assumedhomedrive\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe`""
		"System32\drivers\evbda.sys"
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /svc"
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /medsvc"
		"$env_assumedhomedrive\Windows\System32\lsass.exe"
		"System32\drivers\EhStorClass.sys"
		"System32\drivers\EhStorTcgDrv.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k appmodel -p"
		"$env_assumedhomedrive\Windows\System32\drivers\errdev.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\fxssvc.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\fdc.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\filecrypt.sys"
		"System32\drivers\fileinfo.sys"
		"`"$env_assumedhomedrive\Program Files\Microsoft OneDrive\*\FileSyncHelper.exe`""
		"system32\drivers\filetrace.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\flpydisk.sys"
		"system32\drivers\fltmgr.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\Microsoft.Net\Framework64\v*\WPF\PresentationFontCache.exe"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k Camera"
		"System32\drivers\FsDepends.sys"
		"System32\DRIVERS\fvevol.sys"
		"`"$env_assumedhomedrive\Program Files\NVIDIA Corporation\FrameViewSDK\nvfvsdksvc_x64.exe`" -service"
		#"`"$env_assumedhomedrive\Program Files (x86)\ASUS\GameSDK Service\GameSDK.exe`""
		"$env_assumedhomedrive\Windows\System32\drivers\vmgencounter.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\genericusbfn.inf_amd64_*\genericusbfn.sys"
		"`"$env_assumedhomedrive\Program Files\Google\Chrome\Application\*\elevation_service.exe`""
		#"system32\DRIVERS\googledrive*.sys"
		"System32\Drivers\msgpioclx.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\gpuenergydrv.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup"
		#"`"$env_assumedhomedrive\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /svc"
		#"`"$env_assumedhomedrive\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /medsvc"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\hcmon.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\HdAudio.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\HDAudBus.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\HidBatt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hidbth.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hidi2c.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hidinterrupt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hidir.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\hidspi.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hidusb.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetSvcs -p"
		"System32\drivers\hnswfpdriver.sys"
		"System32\drivers\HpSAMD.sys"
		"system32\drivers\HTTP.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hvcrash.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\hvservice.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\hvsocketcontrol.sys"
		"System32\Drivers\mshwnclx.sys"
		"System32\drivers\hwpolicy.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\hyperkbd.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\HyperVideo.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\i8042prt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iagpio.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iai2c.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_GPIO2.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_GPIO2_BXT_P.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_GPIO2_CNL.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_GPIO2_GLK.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_I2C.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_I2C_BXT_P.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_I2C_CNL.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSS2i_I2C_GLK.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSSi_GPIO.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\iaLPSSi_I2C.sys"
		"System32\drivers\iaStorAVC.sys"
		"System32\drivers\iaStorV.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\ibbus.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\ibtusb.inf_amd64_f75065d93521b024\ibtusb.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		#"`"$env_assumedhomedrive\Program Files\Corsair\CORSAIR iCUE 4 Software\iCUEDevicePluginHost.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\IndirectKmd.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"System32\drivers\intelide.sys"
		"System32\drivers\intelpep.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\intelpmax.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\intelppm.sys"
		"system32\drivers\iorate.sys"
		"system32\DRIVERS\ipfltdrv.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetSvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\IPMIDrv.sys"
		"System32\drivers\ipnat.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\ipt.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\isapnp.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\msiscsi.sys"
		"System32\drivers\ItSas35i.sys"
		#"`"$env_assumedhomedrive\Program Files\JetBrains\ETW Host\16\JetBrains.Etw.Collector.Host.exe`""
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\dal.inf_*\jhi_service.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\kbdclass.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\kbdhid.sys"
		"system32\drivers\kbldfltr.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\kdnic.sys"
		"$env_assumedhomedrive\Windows\system32\lsass.exe"
		"System32\Drivers\ksecdd.sys"
		"System32\Drivers\ksecpkg.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\ksthunk.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p"
		"System32\drivers\l2bridge.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"`"$env_assumedhomedrive\Program Files\LGHUB\lghub_updater.exe`" --run-as-service"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p"
		"`"$env_assumedhomedrive\Program Files (x86)\LightingService\LightingService.exe`""
		"system32\drivers\lltdio.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_generic_hid_filter.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_joy_bus_enum.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_joy_hid_filter.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_joy_hid_lo.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_joy_vir_hid.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\logi_joy_xlcore.sys"
		"System32\drivers\lsi_sas.sys"
		"System32\drivers\lsi_sas2i.sys"
		"System32\drivers\lsi_sas3i.sys"
		"System32\drivers\lsi_sss.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\system32\drivers\luafv.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs"
		"system32\drivers\lxss.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\System32\drivers\mausbhost.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mausbip.sys"
		"$env_assumedhomedrive\Windows\System32\Drivers\MbamChameleon.sys"
		"system32\DRIVERS\MbamElam.sys"
		"`"$env_assumedhomedrive\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe`""
		"$env_assumedhomedrive\Windows\System32\Drivers\mbamswissarmy.sys"
		"system32\drivers\MbbCx.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k McpManagementServiceGroup"
		"System32\drivers\megasas.sys"
		"System32\drivers\MegaSas2i.sys"
		"System32\drivers\megasas35i.sys"
		"System32\drivers\megasr.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\heci.inf_amd64_*\x64\TeeDriverW10x64.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft\Edge\Application\*\elevation_service.exe`""
		"$env_assumedhomedrive\Windows\System32\drivers\Microsoft.Bluetooth.AvrcpTransport.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\mlx4_bus.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\mmcss.sys"
		"system32\drivers\modem.sys"
		#"`"$env_assumedhomedrive\Program Files\MongoDB\Server\*\bin\mongod.exe`" --config `"$env_assumedhomedrive\Program Files\MongoDB\Server\*\bin\mongod.cfg`" --service"
		"$env_assumedhomedrive\Windows\System32\drivers\monitor.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mouclass.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mouhid.sys"
		"System32\drivers\mountmgr.sys"
		"\??\$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Definition Updates\{*}\MpKslDrv.sys"
		"System32\drivers\mpsdrv.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p"
		"$env_assumedhomedrive\Windows\system32\drivers\mrxdav.sys"
		"system32\DRIVERS\mrxsmb.sys"
		"system32\DRIVERS\mrxsmb20.sys"
		"System32\drivers\bridge.sys"
		"$env_assumedhomedrive\Windows\System32\msdtc.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\msgpiowin32.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mshidkmdf.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mshidumdf.sys"
		"\??\$env_assumedhomedrive\Windows\system32\drivers\MsIo64.sys"
		"System32\drivers\msisadrv.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\msiexec.exe /V"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\MSKSSRV.sys"
		"system32\drivers\mslldp.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\MSPCLOCK.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\MSPQM.sys"
		"system32\drivers\msquic.sys"
		"system32\drivers\msseccore.sys"
		"system32\drivers\mssecflt.sys"
		"system32\drivers\mssecwfp.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\mssmbios.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\MSTEE.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\MTConfig.sys"
		"System32\Drivers\mup.sys"
		"System32\drivers\mvumis.sys"
		"system32\DRIVERS\nwifi.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetSvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		"$env_assumedhomedrive\Windows\System32\drivers\ndfltr.sys"
		"system32\drivers\ndis.sys"
		"System32\drivers\ndiscap.sys"
		"System32\drivers\NdisImPlatform.sys"
		"System32\DRIVERS\ndistapi.sys"
		"system32\drivers\ndisuio.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\NdisVirtualBus.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\ndiswan.sys"
		"System32\DRIVERS\ndiswan.sys"
		"system32\drivers\NDKPing.sys"
		"System32\DRIVERS\NDProxy.sys"
		"system32\drivers\Ndu.sys"
		"system32\drivers\NetAdapterCx.sys"
		"system32\drivers\netbios.sys"
		"System32\DRIVERS\netbt.sys"
		"$env_assumedhomedrive\Windows\system32\lsass.exe"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\Microsoft.NET\Framework64\v*\SMSvcHost.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\netvsc.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\Netwtw10.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\Netwtw12.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\npcap.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\npsvctrig.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"system32\drivers\nsiproxy.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetSvcs"
		"`"$env_assumedhomedrive\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe`" -s NvContainerLocalSystem -f `"$env_assumedhomedrive\ProgramData\NVIDIA\NvContainerLocalSystem.log`" -l 3 -d `"$env_assumedhomedrive\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem`" -r -p 30000 -st `"$env_assumedhomedrive\Program Files\NVIDIA Corporation\NvContainer\NvContainerTelemetryApi.dll`""
		"System32\drivers\nvdimm.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\Display.NvContainer\NVDisplay.Container.exe -s NVDisplay.ContainerLocalSystem -f $env_assumedhomedrive\ProgramData\NVIDIA\NVDisplay.ContainerLocalSystem.log -l 3 -d $env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\Display.NvContainer\plugins\LocalSystem -r -p 30000 -cfg NVDisplay.ContainerLocalSystem\LocalSystem"
		"$env_assumedhomedrive\Windows\system32\drivers\nvhda64v.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\nvlddmkm.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\nvmoduletracker.inf_amd64_*\NvModuleTracker.sys"
		"System32\drivers\nvraid.sys"
		"System32\drivers\nvstor.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\nvvad64v.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\nvvhci.sys"
		"`"$env_assumedhomedrive\Program Files\Microsoft OneDrive\*\OneDriveUpdaterService.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"System32\drivers\p9rdr.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\parport.sys"
		"System32\drivers\partmgr.sys"
		"system32\drivers\passthruparser.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\pci.sys"
		"System32\drivers\pciide.sys"
		"System32\drivers\pcmcia.sys"
		"System32\drivers\pcw.sys"
		"system32\drivers\pdc.sys"
		"system32\drivers\peauth.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k PeerDist"
		"$env_assumedhomedrive\Windows\system32\PerceptionSimulation\PerceptionSimulationService.exe"
		"System32\drivers\percsas2i.sys"
		"System32\drivers\percsas3i.sys"
		"$env_assumedhomedrive\Windows\SysWow64\perfhost.exe"
		#"$env_assumedhomedrive`\Program Files (x86)\PgBouncer\bin\pgbouncer.exe --service `"$env_assumedhomedrive\Program Files (x86)\PgBouncer\share\pgbouncer.ini`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"system32\drivers\PktMon.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		#"$env_assumedhomedrive\Program Files (x86)\GeoComply\//PlayerLocationCheck///Application/service.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"System32\drivers\pmem.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\pnpmem.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\portcfg.sys"
		#"`"$env_assumedhomedrive\Program Files\PostgreSQL\14\bin\pg_ctl.exe`" runservice -N `"postgresql-x64-14`" -D `"$env_assumedhomedrive\Program Files\PostgreSQL\14\data`" -w"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\System32\drivers\raspptp.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k print"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k PrintWorkflow"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k PrintWorkflow"
		#"`"$env_assumedhomedrive\Program Files\Private Internet Access\pia-service.exe`""
		#"`"$env_assumedhomedrive\Program Files\Private Internet Access\pia-wgservice.exe`" `"$env_assumedhomedrive\Program Files\Private Internet Access\data\wgpia0.conf`""
		"$env_assumedhomedrive\Windows\System32\drivers\processr.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\pacer.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"system32\drivers\pvhdparser.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$env_assumedhomedrive\Windows\system32\drivers\qwavedrv.sys"
		"`"$env_assumedhomedrive\Program Files\erl-*\erts-*\bin\erlsrv.exe`""
		"system32\DRIVERS\ramdisk.sys"
		"System32\DRIVERS\rasacd.sys"
		#"$env_assumedhomedrive\Windows\System32\drivers\AgileVpn.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\rasl2tp.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs"
		"System32\DRIVERS\raspppoe.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\rassstp.sys"
		"system32\DRIVERS\rdbss.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\rdpbus.sys"
		"System32\drivers\rdpdr.sys"
		"System32\drivers\rdpvideominiport.sys"
		"System32\drivers\rdyboost.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k localService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k rdxgroup"
		"$env_assumedhomedrive\Windows\System32\drivers\rfcomm.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\rhproxy.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted"
		#"`"$env_assumedhomedrive\Program Files\Rockstar Games\Launcher\RockstarService.exe`""
		#"`"$env_assumedhomedrive\Program Files\ASUS\ROG Live Service\ROGLiveService.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k RPCSS -p"
		"$env_assumedhomedrive\Windows\system32\locator.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k rpcss -p"
		"system32\drivers\rspndr.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vms3cap.sys"
		"$env_assumedhomedrive\Windows\system32\lsass.exe"
		"System32\drivers\sbp2port.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted"
		"System32\DRIVERS\scfilter.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\scmbus.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs"
		"$env_assumedhomedrive\Windows\System32\drivers\sdbus.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\SDFRd.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k SDRSVC"
		"$env_assumedhomedrive\Windows\System32\drivers\sdstor.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\SecurityHealthService.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"`"$env_assumedhomedrive\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe`""
		"$env_assumedhomedrive\Windows\System32\SensorDataService.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"system32\drivers\SerCx.sys"
		"system32\drivers\SerCx2.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\serenum.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\serial.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\sermouse.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\sfloppy.sys"
		"system32\drivers\SgrmAgent.sys"
		"$env_assumedhomedrive\Windows\system32\SgrmBroker.exe"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"System32\drivers\SiSRaid2.sys"
		"System32\drivers\sisraid4.sys"
		"System32\drivers\SmartSAMD.sys"
		"System32\DRIVERS\smbdirect.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k smphost"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\snmptrap.exe"
		"system32\drivers\spaceparser.sys"
		"System32\drivers\spaceport.sys"
		"System32\drivers\SpatialGraphFilter.sys"
		"system32\drivers\SpbCx.sys"
		"$env_assumedhomedrive\Windows\system32\spectrum.exe"
		"$env_assumedhomedrive\Windows\System32\spoolsv.exe"
		"$env_assumedhomedrive\Windows\system32\sppsvc.exe"
		"System32\DRIVERS\srv2.sys"
		"System32\DRIVERS\srvnet.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$env_assumedhomedrive\Windows\System32\OpenSSH\ssh-agent.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k appmodel -p"
		"`"$env_assumedhomedrive\Program Files (x86)\Common Files\Steam\steamservice.exe`" /RunAsService"
		"System32\drivers\stexstor.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k imgsvc"
		"System32\drivers\storahci.sys"
		"System32\drivers\vmstorfl.sys"
		"System32\drivers\stornvme.sys"
		"system32\drivers\storqosflt.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\storufs.sys"
		"System32\drivers\storvsc.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\storvsp.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\swenum.inf_amd64_*\swenum.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k swprv"
		"$env_assumedhomedrive\Windows\System32\drivers\Synth3dVsc.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\tap-pia-*.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"System32\drivers\tcpip.sys"
		"System32\drivers\tcpip.sys"
		"System32\drivers\tcpipreg.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\tdx.sys"
		#"`"$env_assumedhomedrive\Program Files\TeamViewer\TeamViewer_Service.exe`""
		"System32\drivers\IntelTA.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\terminpt.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService"
		"$env_assumedhomedrive\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\TieringEngineService.exe"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\tpm.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\servicing\TrustedInstaller.exe"
		"system32\drivers\tsusbflt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\TsUsbGD.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\tsusbhub.sys"
		"System32\drivers\tunnel.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\drivers\uaspstor.sys"
		"System32\Drivers\UcmCx.sys"
		"System32\Drivers\UcmTcpciCx.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\UcmUcsiAcpiClient.sys"
		"System32\Drivers\UcmUcsiCx.sys"
		"system32\drivers\ucx01000.sys"
		"system32\drivers\udecx.sys"
		"system32\DRIVERS\udfs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UdkSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UdkSvcGroup"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\uefi.inf_amd64_*\UEFI.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\UevAgentDriver.sys"
		"$env_assumedhomedrive\Windows\system32\AgentService.exe"
		"system32\drivers\ufx01000.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\ufxchipidea.inf_amd64_*\UfxChipidea.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\ufxsynopsys.sys"
		"`"$env_assumedhomedrive\Program Files\Microsoft Update Health Tools\uhssvc.exe`""
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\umbus.inf_amd64_*\umbus.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\umpass.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\urschipidea.inf_amd64_*\urschipidea.sys"
		"system32\drivers\urscx01000.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\urssynopsys.inf_amd64_*\urssynopsys.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\usbaudio.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbaudio2.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbccgp.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbcir.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbehci.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbhub.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\UsbHub3.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbohci.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbprint.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usb80236.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\usbser.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\USBSTOR.SYS"
		"$env_assumedhomedrive\Windows\System32\drivers\usbuhci.sys"
		"$env_assumedhomedrive\Windows\System32\Drivers\usbvideo.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\USBXHCI.SYS"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\lsass.exe"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\VBoxNetAdp6.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\VBoxNetLwf.sys"
		"`"$env_assumedhomedrive\Program Files\Oracle\VirtualBox\VBoxSDS.exe`""
		"$env_assumedhomedrive\Windows\system32\DRIVERS\VBoxSup.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\VBoxUSBMon.sys"
		"System32\drivers\vdrvroot.sys"
		"$env_assumedhomedrive\Windows\System32\vds.exe"
		"System32\drivers\VerifierExt.sys"
		"system32\drivers\vfpext.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vhdmp.sys"
		"system32\drivers\vhdparser.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vhf.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\Vid.sys"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\vrd.inf_amd64_*\vrd.sys"
		#"`"$env_assumedhomedrive\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe`""
		"System32\drivers\vmbus.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\VMBusHID.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vmbusr.sys"
		"System32\drivers\vmci.sys"
		"$env_assumedhomedrive\Windows\system32\vmcompute.exe"
		"$env_assumedhomedrive\Windows\System32\drivers\vmgid.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k ICService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k ICService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\vmnetadapter.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\vmnetbridge.sys"
		"$env_assumedhomedrive\Windows\SysWOW64\vmnetdhcp.exe"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\vmnetuserif.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vmswitch.sys"
		"system32\drivers\VmsProxyHNic.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\VmsProxyHNic.sys"
		"System32\drivers\vmswitch.sys"
		"system32\drivers\VmsProxy.sys"
		"System32\drivers\vmswitch.sys"
		"System32\drivers\vmswitch.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vmusb.sys"
		# "`"$env_assumedhomedrive\Program Files (x86)\Common Files\VMware\USB\vmware-usbarbitrator64.exe`""
		"$env_assumedhomedrive\Windows\SysWOW64\vmnat.exe"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\vmx86.sys"
		"$env_assumedhomedrive\Windows\system32\drivers\mvvad.sys"
		"System32\drivers\volmgr.sys"
		"System32\drivers\volmgrx.sys"
		"System32\drivers\volsnap.sys"
		"System32\drivers\volume.sys"
		"System32\drivers\vpci.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vpcivsp.sys"
		"System32\drivers\vsmraid.sys"
		"system32\DRIVERS\vsock.sys"
		"$env_assumedhomedrive\Windows\system32\vssvc.exe"
		"`"$env_assumedhomedrive\Program Files (x86)\Microsoft Visual Studio\Shared\Common\DiagnosticsHub.Collection.Service\StandardCollector.Service.exe`""
		"SysWOW64\drivers\vstor2-x64.sys"
		"System32\drivers\vstxraid.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vwifibus.sys"
		"System32\drivers\vwififlt.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\vwifimp.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k wusvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\wacompen.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k appmodel -p"
		"System32\DRIVERS\wanarp.sys"
		"System32\DRIVERS\wanarp.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted"
		"`"$env_assumedhomedrive\Windows\system32\wbengine.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k WbioSvcGroup"
		"$env_assumedhomedrive\Windows\system32\drivers\wcifs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$env_assumedhomedrive\Windows\system32\drivers\wcnfs.sys"
		"system32\drivers\wd\WdBoot.sys"
		"system32\drivers\Wdf01000.sys"
		"system32\drivers\wd\WdFilter.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\DRIVERS\wdiwifi.sys"
		"system32\drivers\WdmCompanionFilter.sys"
		"system32\drivers\wd\WdNisDrv.sys"
		"`"$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe`""
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k WepHostSvcGroup"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k WerSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"System32\drivers\wfplwfs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\wimmount.sys"
		"`"$env_assumedhomedrive\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`""
		"system32\drivers\WindowsTrustedRT.sys"
		"System32\drivers\WindowsTrustedRTProxy.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\System32\drivers\winmad.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"system32\drivers\winnat.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k NetworkService -p"
		"$env_assumedhomedrive\Windows\System32\drivers\WinUSB.SYS"
		"$env_assumedhomedrive\Windows\System32\drivers\winverbs.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\wmiacpi.sys"
		"$env_assumedhomedrive\Windows\system32\wbem\WmiApSrv.exe"
		"$env_assumedhomedrive\Windows\System32\DriverStore\FileRepository\mewmiprov.inf_amd64_*\WMIRegistrationService.exe"
		"`"$env_assumedhomedrive\Program Files\Windows Media Player\wmpnetwk.exe`""
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalService -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalService"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted"
		"System32\drivers\WpdUpFltr.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$env_assumedhomedrive\Windows\system32\drivers\ws2ifsl.sys"
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\SearchIndexer.exe /Embedding"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"system32\drivers\WudfPf.sys"
		"$env_assumedhomedrive\Windows\System32\drivers\WUDFRd.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\WUDFRd.sys"
		"$env_assumedhomedrive\Windows\system32\DRIVERS\WUDFRd.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\xboxgip.sys"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\system32\svchost.exe -k netsvcs -p"
		"$env_assumedhomedrive\Windows\System32\drivers\xinputhid.sys"
		"`"$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\Windows Live\WLIDSVC.EXE`""
		"$env_assumedhomedrive\Windows\System32\svchost.exe -k secsvcs"
		"system32\DRIVERS\wfplwf.sys"
		"C:\Windows\system32\drivers\wd.sys"
		"C:\Windows\system32\Wat\WatAdminSvc.exe"
		"system32\DRIVERS\vwifibus.sys"
		"C:\Windows\system32\drivers\vsmraid.sys"
		"C:\Windows\system32\drivers\vmbus.sys"
		"C:\Windows\system32\drivers\viaide.sys"
		"system32\DRIVERS\vhdmp.sys"
		"System32\drivers\rdvgkmd.sys"
		"C:\Windows\System32\drivers\vga.sys"
		"system32\DRIVERS\vgapnp.sys"
		"system32\DRIVERS\usbuhci.sys"
		"system32\DRIVERS\USBSTOR.SYS"
		"system32\DRIVERS\usbhub.sys"
		"system32\DRIVERS\usbehci.sys"
		"system32\DRIVERS\umbus.sys"
		"C:\Windows\system32\drivers\uliagpkx.sys"
		"C:\Windows\system32\drivers\uagp35.sys"
		"system32\drivers\tsusbhub.sys"
		"System32\drivers\truecrypt.sys"
		"System32\DRIVERS\tssecsrv.sys"
		"system32\drivers\tpm.sys"
		"system32\DRIVERS\termdd.sys"
		"system32\DRIVERS\tdx.sys"
		"system32\drivers\tdtcp.sys"
		"system32\drivers\tdpipe.sys"
		"System32\drivers\synth3dvsc.sys"
		"system32\DRIVERS\swenum.sys"
		"C:\Windows\system32\drivers\storvsc.sys"
		"C:\Windows\system32\drivers\stexstor.sys"
		"System32\DRIVERS\srv.sys"
		"system32\DRIVERS\smb.sys"
		"C:\Windows\system32\drivers\sisraid4.sys"
		"C:\Windows\system32\drivers\SiSRaid2.sys"
		"C:\Windows\system32\drivers\sffp_sd.sys"
		"C:\Windows\system32\drivers\sffp_mmc.sys"
		"C:\Windows\system32\drivers\sbp2port.sys"
		"C:\Windows\system32\svchost.exe -k regsvc"
		"system32\drivers\rdprefmp.sys"
		"system32\drivers\rdpencdd.sys"
		"System32\DRIVERS\RDPCDD.sys"
		"system32\DRIVERS\rdpbus.sys"
		"system32\DRIVERS\rassstp.sys"
		"system32\DRIVERS\rasl2tp.sys"
		"C:\Windows\system32\drivers\ql40xx.sys"
		"C:\Windows\system32\drivers\ql2300.sys"
		"system32\DRIVERS\raspptp.sys"
		"C:\Windows\system32\drivers\pciide.sys"
		"C:\Windows\system32\drivers\ohci1394.sys"
		"C:\Windows\system32\drivers\nv_agp.sys"
		"C:\Windows\system32\drivers\nvstor.sys"
		"C:\Windows\system32\drivers\nvraid.sys"
		"`"c:\Program Files\Microsoft Security Client\NisSrv.exe`""
		"`"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe`" -NetMsmqActivator"
		"system32\drivers\MSTEE.sys"
		"system32\DRIVERS\mssmbios.sys"
		"system32\drivers\MSPQM.sys"
		"system32\drivers\MSPCLOCK.sys"
		"`"c:\Program Files\Microsoft Security Client\MsMpEng.exe`""
		"system32\drivers\MSKSSRV.sys"
		"C:\Windows\system32\drivers\msdsm.sys"
		"system32\drivers\msahci.sys"
		"system32\DRIVERS\mrxsmb10.sys"
		"C:\Windows\system32\drivers\mpio.sys"
		"system32\DRIVERS\MpFilter.sys"
		"system32\DRIVERS\mouclass.sys"
		"system32\DRIVERS\monitor.sys"
		"system32\DRIVERS\WUDFRd.sys"
		"C:\Windows\system32\drivers\sffdisk.sys"
		"system32\DRIVERS\NisDrvWFP.sys"
		"C:\Windows\system32\drivers\nfrd960.sys"
		"C:\Windows\system32\drivers\lsi_*.sys"
		"system32\DRIVERS\kbdclass.sys"
		"C:\Windows\system32\drivers\isapnp.sys"
		"system32\drivers\irenum.sys"
		"system32\DRIVERS\intelppm.sys"
		"C:\Windows\system32\drivers\iirsp.sys"
		"`"C:\Windows\Microsoft.NET\Framework64\v3.0\Windows Communication Foundation\infocard.exe`""
		"C:\Windows\system32\drivers\iaStorV.sys"
		"system32\DRIVERS\i8042prt.sys"
		"C:\Windows\system32\drivers\HpSAMD.sys"
		"system32\DRIVERS\HDAudBus.sys"
		"system32\drivers\HdAudio.sys"
		"C:\Windows\system32\drivers\hcw85cir.sys"
		"C:\Windows\system32\drivers\gagp30kx.sys"
		"C:\Windows\system32\drivers\elxstor.sys"
		"C:\Windows\ehome\ehsched.exe"
		"C:\Windows\ehome\ehRecvr.exe"
		"C:\Windows\system32\drivers\evbda.sys"
		"system32\DRIVERS\e1e6032e.sys"
		"System32\drivers\discache.sys"
		"C:\Windows\system32\drivers\crcdisk.sys"
		"system32\DRIVERS\CompositeBus.sys"
		"system32\DRIVERS\compbatt.sys"
		"C:\Windows\system32\drivers\cmdide.sys"
		"system32\DRIVERS\CmBatt.sys"
		"C:\Windows\Microsoft.NET\Framework64\v*\mscorsvw.exe"
		"System32\CLFS.sys"
		"system32\DRIVERS\cdrom.sys"
		"C:\Windows\system32\svchost.exe -k bthsvcs"
		"C:\Windows\System32\Drivers\BrUsbSer.sys"
		"C:\Windows\System32\Drivers\BrUsbMdm.sys"
		"C:\Windows\System32\Drivers\BrUsbWdm.sys"
		"C:\Windows\System32\Drivers\Brserid.sys"
		"C:\Windows\System32\Drivers\BrFiltUp.sys"
		"C:\Windows\System32\Drivers\BrFiltLo.sys"
		"system32\DRIVERS\blbdrive.sys"
		"system32\DRIVERS\b57nd60a.sys"
		"C:\Windows\system32\drivers\bxvbda.sys"
		"system32\DRIVERS\athrx.sys"
		"system32\DRIVERS\asyncmac.sys"
		"C:\Windows\Microsoft.NET\Framework64\v*\aspnet_state.exe"
		"C:\Windows\system32\drivers\arcsas.sys"
		"C:\Windows\system32\drivers\arc.sys"
		"C:\Windows\system32\drivers\appid.sys"
		"C:\Windows\system32\IEEtwCollector.exe*"
		"C:\Windows\Microsoft.NET\Framework\v*\mscorsvw.exe"
		"C:\Windows\System32\Drivers\BrSerWdm.sys"
		"C:\Windows\system32\drivers\amdsbs.sys"
		"C:\Windows\system32\drivers\amdsata.sys"
		"C:\Windows\system32\drivers\amdide.sys"
		"C:\Windows\system32\drivers\aliide.sys"
		"C:\Windows\system32\drivers\agp440.sys"
		"C:\Windows\system32\drivers\adpu320.sys"
		"C:\Windows\system32\drivers\adpahci.sys"
		"C:\Windows\system32\drivers\adp94xx.sys"
	)


	#$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
	$service_path = "$regtarget_hklm`SYSTEM\$currentcontrolset\Services"
	$service_list = New-Object -TypeName "System.Collections.ArrayList"
	if (Test-Path -Path "Registry::$service_path") {
		$items = Get-ChildItem -Path "Registry::$service_path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSProvider
			if ($data.ImagePath -ne $null) {
				$service = [PSCustomObject]@{
					Name     = $data.PSChildName
					PathName = $data.ImagePath
				}
				$service.PathName = $service.PathName.Replace("\SystemRoot", "$env_assumedhomedrive\Windows")
				$service_list.Add($service) | Out-Null
			}
		}
	}
	foreach ($service in $service_list) {
		Write-SnapshotMessage -Key $service.Name -Value $service.PathName -Source "Services"

		if ($loadsnapshot) {
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch: Service Name\Path'
				Risk      = 'Medium'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$result = Confirm-IfAllowed $allowtable_services $service.Name $service.PathName $detection
			if ($result) {
				continue
			}
		}
		
		if (Test-RemoteAccessTrojanTerms $service.PathName) {
			# Service has a suspicious launch pattern matching a known RAT
			$detection = [PSCustomObject]@{
				Name      = 'Service Argument has known-RAT Keyword'
				Risk      = 'Medium'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName + ", RAT Keyword: " + $term
			}
			Write-Detection $detection
		}
			
		if ($service.PathName -match "$env_assumedhomedrive\\Windows\\Temp\\.*") {
			# Service launching from Windows\Temp
			$detection = [PSCustomObject]@{
				Name      = 'Service Launching from Windows Temp Directory'
				Risk      = 'High'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			Write-Detection $detection
		}
		# Detection - Non-Standard Tasks
		foreach ($i in $default_service_exe_paths) {
			if ( $service.PathName -like $i) {
				$exe_match = $true
				break
			}
			elseif ($service.PathName.Length -gt 0) {
				$exe_match = $false
			}
		}
		if ($exe_match -eq $false) {
			# Current Task Executable Path is non-standard
			$detection = [PSCustomObject]@{
				Name      = 'Non-Standard Service Path'
				Risk      = 'Low'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			Write-Detection $detection
		}
		if ($service.PathName -match ".*cmd.exe /(k|c).*") {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching from cmd.exe'
				Risk      = 'Medium'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			Write-Detection $detection
		}
		if ($service.PathName -match ".*powershell.exe.*") {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching from powershell.exe'
				Risk      = 'Medium'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			Write-Detection $detection
		}

		if (Test-TrawlerSuspiciousTerms $service.PathName) {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching with suspicious keywords'
				Risk      = 'High'
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			Write-Detection $detection
		}
	}
}


function Search-ServicesByRegex {
	# TODO - Check FailureCommand for abnormal entries
	# Supports Drive Retargeting
	# Support Dynamic Snapshotting
	Write-Message "Checking Service Registry Entries"
	# Service DLL Inspection
	$homedrive = $env_homedrive

	$path = "{0}SYSTEM\$currentcontrolset\Services" -f $regtarget_hklm
	if (Test-Path -Path "Registry::$path") {
		$services = Get-ChildItem -Path "Registry::$path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($service in $services) {
			$service_path = "Registry::" + $service.Name
			$service_children_keys = Get-ChildItem -Path "$service_path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$service_data = Get-ItemProperty -Path $service_path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$service_data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'ImagePath') {
					Write-SnapshotMessage -Key $service.Name -Value $_.Value -Source 'Services_REG'

					if ($loadsnapshot) {
						$detection = [PSCustomObject]@{
							Name      = 'Allowlist Mismatch: Possible Service Hijack - Unexpected ImagePath Location'
							Risk      = 'Medium'
							Source    = 'Services'
							Technique = "T1543.003: Create or Modify System Process: Windows Service"
							Meta      = "Key: " + $service.Name + ", Value: " + $_.Value + ", Regex Expected Location: " + $image_path_lookup[$service.Name]
						}
						$result = Confirm-IfAllowed $allowtable_services_reg $service.Name $_.Value $_.Value $detection
						if ($result) {
							continue
						}
					}
					if ($image_path_lookup.ContainsKey($service.Name)) {
						if ($_.Value -notmatch $image_path_lookup[$service.Name]) {
							$detection = [PSCustomObject]@{
								Name      = 'Possible Service Hijack - Unexpected ImagePath Location'
								Risk      = 'Medium'
								Source    = 'Services'
								Technique = "T1543.003: Create or Modify System Process: Windows Service"
								Meta      = "Key: " + $service.Name + ", Value: " + $_.Value + ", Regex Expected Location: " + $image_path_lookup[$service.Name]
							}
							Write-Detection $detection
						}
					}
					elseif (1 -eq 1) {
					}
				}
			}
			foreach ($child_key in $service_children_keys) {
				#Write-Host $child_key.Name
				$child_path = "Registry::" + $child_key.Name
				$data = Get-ItemProperty -Path $child_path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				$data.PSObject.Properties | ForEach-Object {
					if ($_.Name -eq "ServiceDll") {
						Write-SnapshotMessage -Key $child_key.Name -Value $_.Value -Source 'Services_REG'

						if ($loadsnapshot) {
							$detection = [PSCustomObject]@{
								Name      = 'Allowlist Mismatch: Possible Service Hijack - Unexpected ServiceDll Location'
								Risk      = 'Medium'
								Source    = 'Services'
								Technique = "T1543.003: Create or Modify System Process: Windows Service"
								Meta      = "Key: " + $child_key.Name + ", Value: " + $_.Value + " Regex Expected Location: " + $service_dll_lookup[$child_key.Name]
							}
							$result = Confirm-IfAllowed $allowtable_services_reg $child_key.Name $_.Value $_.Value $detection
							if ($result) {
								continue
							}
						}
						if ($service_dll_lookup.ContainsKey($child_key.Name)) {
							if ($_.Value -notmatch $service_dll_lookup[$child_key.Name]) {
								#Write-Host "NAME:"$child_key.Name
								#Write-Host "DETECTION: "$_.Value", Original: "$service_dll_lookup[$child_key.Name]
								$detection = [PSCustomObject]@{
									Name      = 'Possible Service Hijack - Unexpected ServiceDll Location'
									Risk      = 'Medium'
									Source    = 'Services'
									Technique = "T1543.003: Create or Modify System Process: Windows Service"
									Meta      = "Key: " + $child_key.Name + ", Value: " + $_.Value + ", Regex Expected Location: " + $service_dll_lookup[$child_key.Name]
								}
								Write-Detection $detection
							}
						}
						elseif (1 -eq 1) {
						}
					}
				}
			}
		}
	}

}