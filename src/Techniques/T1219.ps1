function Check-RATS {
    # Supports Drive Retargeting

    # https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects.html
    # https://vikas-singh.notion.site/vikas-singh/Remote-Access-Software-Forensics-3e38d9a66ca0414ca9c882ad67f4f71b#183d1e94c9584aadbb13779bbe77f68e
    # https://support.solarwinds.com/SuccessCenter/s/article/Log-File-Locations-Adjustments-and-Diagnostics-for-DameWare?language=en_US
    # https://digitalforensicsdotblog.wordpress.com/tag/screenconnect/
    # https://docs.getscreen.me/faq/agent/
    # https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
    # https://support.goto.com/resolve/help/where-do-i-find-goto-resolve-application-logs
    # https://support.radmin.com/index.php/Knowledgebase/Article/View/124/9/Radmin-Installation-Guide

    ##### TightVNC
    # -Log Files
    ##### UltraVNC
    # -Log Files
    ##### RealVNC
    # -Debug Logs - %ProgramData%\RealVBC-Service\vncserver.log
    ##### AmmyAdmin
    # -LogFiles
    ##### Remote
    ##### AnyDesk
    # -Log Files
    ##### TeamViewer
    # -Log Files
    # HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer
    ##### NinjaOne
    ##### Zoho GoTo Assist/GoTo Resolve
    ##### Atera
    # https://support.atera.com/hc/en-us/articles/215955967-Troubleshoot-the-Atera-Agent-Windows-
    # HKEY_LOCAL_MACHINE\SOFTWARE\ATERA Networks\AlphaAgent
    # If Reg key exists, Agent was installed at one point
    # Also installs a service named 'AlteraAgent'
    ##### ConnectWise/ScreenConnect
    # https://blog.morphisec.com/connectwise-control-abused-again-to-deliver-zeppelin-ransomware
    # Installs service called "ScreenConnect Client"
    # C:\ProgramData\ScreenConnect Client (<string ID>)\user.config
    # C:\Windows\Temp\ScreenConnect\.*\
    ##### AnyScreen
    ##### RemotePC
    ##### BeyondTrust
    ##### Remote Desktop Manager
    ##### Getscreen
    ##### Action1
    ##### Webex
    ##### Atlassian
    ##### Surfly
    ##### Electric
    ##### Pulseway
    ##### Kaseya VSA
    ##### XMReality
    ##### SightCall
    ##### DameWare
    ##### ScreenMeet
    ##### Viewabo
    ##### ShowMyPC
    ##### Iperius
    ##### Radmin
    ##### Remote Utilities
    ##### RemoteToPC
    ##### LogMeIn
    Write-Message "Checking Common RAT Artifacts"

    $application_logpaths = @{
        "Action1 (Dir 1)" = "$env_homedrive\Windows\Action1"
        "Action1 (Log 1)" = "$env_homedrive\Windows\Action1\Action1_log_*.log"
        "AmmyAdmin (Log 1)" = "$env_programdata\AMMYY\access.log"
        "AmmyAdmin (Dir 1)" = "$env_programdata\AMMYY"
        "AnyDesk (Dir 1)" = "$env_programdata\AnyDesk"
        "AnyDesk (Dir 2)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\AnyDesk"
        "AnyDesk (Log 1)" = "$env_programdata\AnyDesk\ad.trace"
        "AnyDesk (Log 2)" = "$env_programdata\AnyDesk\connection_trace.txt"
        "AnyDesk (Log 3)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\AnyDesk\ad.trace"
        "AnyDesk (Log 4)" = "$env_programdata\AnyDesk\ad_svc.trace"
        "AnyDesk (Log 5)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\AnyDesk\*.conf"
        "AnyDesk (Reg 1)" = "Registry::{0}SYSTEM\*\Services\AnyDesk" -f $regtarget_hklm
        "AnyDesk (Reg 2)" = "Registry::{0}SOFTWARE\Clients\Media\AnyDesk" -f $regtarget_hklm
        "AnyScreen" = ""
        "Bomgar\BeyondTrust (Dir 1)" = "$env_homedrive\Program Files\Bomgar"
        "Bomgar\BeyondTrust (Dir 2)" = "$env_homedrive\Program Files (x86)\Bomgar"
        "Bomgar\BeyondTrust (Dir 3)" = "$env_programdata\BeyondTrust"
        "Atera\SplashTop (Log 1)" = "$env_homedrive\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log.txt"
        "Atera\SplashTop (Log 2)" = "$env_homedrive\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\*.txt"
        "Atera\SplashTop (Dir 1)" = "$env_homedrive\Program Files\ATERA Networks\AteraAgent"
        "Atera\SplashTop (Dir 2)" = "$env_homedrive\Program Files\ATERA Networks"
        "Atera\SplashTop (Dir 3)" = "$env_homedrive\Program Files (x86)\ATERA Networks"
        "Atera\SplashTop (Reg 1)" = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32" -f $regtarget_hklm
        "Atera\SplashTop (Reg 2)" = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS" -f $regtarget_hklm
        "Atera\SplashTop (Reg 3)" = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AlphaAgent" -f $regtarget_hklm
        "Atera\SplashTop (Reg 4)" = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AteraAgent" -f $regtarget_hklm
        "Atera\SplashTop (Reg 5)" = "Registry::{0}SYSTEM\*\Services\AteraAgent" -f $regtarget_hklm
        "Atera\SplashTop (Reg 6)" = "Registry::{0}SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational" -f $regtarget_hklm
        "Atera\SplashTop (Reg 7)" = "Registry::{0}SYSTEM\*\Services\SplashtopRemoteService" -f $regtarget_hklm
        "Atera\SplashTop (Reg 8)" = "Registry::{0}SYSTEM\*\Control\SafeBoot\Network\SplashtopRemoteService" -f $regtarget_hklm
        "Atera\SplashTop (Reg 9)" = "Registry::{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF Remote Printer" -f $regtarget_hklm
        "Atera\SplashTop (Reg 10)" = "Registry::{0}SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo" -f $regtarget_hklm
        "Citrix\GoToMyPC (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\GoTo"
        "Citrix\GoToMyPC (Log 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\GoTo\Logs\goto.log"
        "Citrix\GoToMyPC (Reg 1)" = "Registry::{0}SOFTWARE\WOW6432Node\Citrix\GoToMyPc" -f $regtarget_hklm
        "Citrix\GoToMyPC (Reg 2)" = "Registry::{0}SOFTWARE\Citrix\GoToMyPc\FileTransfer" -f $regtarget_hkcu
        "ConnectWise\ScreenConnect (Dir 1)" = "$env_programdata\ScreenConnect*"
        "ConnectWise\ScreenConnect (Dir 2)" = "$env_homedrive\Program Files (x86)\ScreenConnect*"
        "ConnectWise\ScreenConnect (Dir 3)" = "$env_homedrive\Program Files\ScreenConnect*"
        "ConnectWise\ScreenConnect (Dir 4)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\Temp\ScreenConnect*"
        "ConnectWise\ScreenConnect (Dir 5)" = "$env_homedrive\Windows\temp\ScreenConnect*"
        "ConnectWise\ScreenConnect (Dir 6)" = "$env_homedrive\Users\USER_REPLACE\Documents\ConnectWiseControl"
        "DameWare (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\temp\dwrrcc downloads"
        "DameWare (Dir 2)" = "$env_homedrive\Windows\dwrcs"
        "Dameware (Dir 3)" = "$env_programdata\DameWare"
        "DameWare (Dir 4)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\DameWare Development"
        "Dameware (Dir 5)" = "$env_programdata\DameWare Development"
        "GetScreen (Dir 1)" = "$env_homedrive\Program Files\Getscreen.me"
        "GetScreen (Dir 2)" = "$env_programdata\Getscreen.me"
        "Iperius (Dir 1)" = "$env_programdata\iperius*"
        "Iperius (Dir 2)" = "$env_homedrive\Program Files\iperius*"
        "Kaseya VSA (Dir 1)" = "$env_programdata\Kaseya*"
        "Kaseya VSA (Dir 2)" = "$env_homedrive\Program Files (x86)\Kaseya*"
        "Kaseya VSA (Dir 3)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\Kaseya*"
        "Level (Dir 1)" = "$env_homedrive\Program Files (x86)\Level"
        "Level (Dir 2)" = "$env_homedrive\Program Files\Level"
        "Level (Log 1)" = "$env_homedrive\Windows\Temp\level-windows-*"
        "LogMeIn (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\LogMeInIgnition*"
        "LogMeIn (Dir 2)" = "$env_homedrive\ProgramData\LogMeIn"
        "NinjaOne" = ""
        "Pulseway (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\Pulseway Remote Control"
        "Pulseway (Reg 1)" = "Registry::HKCU\Software\MMSOFT Design\Pulseway\Remote Desktop"
        "Pulseway (Reg 2)" = "Registry::{0}Software\MMSOFT Design\Pulseway\Remote Desktop" -f $regtarget_hklm
        "Radmin (Dir 1)" = "$env_homedrive\Program Files\Radmin*"
        "Radmin (Dir 2)" = "$env_homedrive\Program Files (x86)\Radmin*"
        "RealVNC (Dir 1)" = "$env_programdata\RealVBC-Service"
        "RealVNC (Log 1)" = "$env_programdata\RealVBC-Service\vncserver.log"
        "RealVNC (Log 2)" = "$env_programdata\RealVBC-Service\vncserver.log.bak"
        "Remote Desktop Manager (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\Devolutions\RemoteDesktopManager"
        "Remote Desktop Manager (Dir 2)" = "$env_homedrive\Program Files (x86)\Devolutions\Remote Desktop Manager"
        "Remote Desktop Manager (Dir 3)" = "$env_homedrive\Program Files\Devolutions\Remote Desktop Manager"
        "RemotePC (Dir 1)" = "$env_programdata\RemotePC*"
        "RemotePC (Dir 2)" = "$env_homedrive\Program Files (x86)\RemotePC*"
        "RemotePC (Dir 3)" = "$env_homedrive\Program Files\RemotePC*"
        "RemotePC (Dir 4)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\RemotePC*"
        "RemoteToPC (Dir 1)" = "$env_programdata\RemoteToPC*"
        "RemoteToPC (Dir 2)" = "$env_homedrive\Program Files (x86)\RemoteToPC*"
        "RemoteToPC (Dir 3)" = "$env_homedrive\Program Files\RemoteToPC*"
        "RemoteToPC (Dir 4)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\RemoteToPC*"
        "Remote Utilities (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\Remote Utilities Agent"
        "Remote Utilities (Dir 2)" = "$env_homedrive\Program Files (x86)\Remote Utilities*"
        "Remote Utilities (Dir 3)" = "$env_homedrive\Program Files\Remote Utilities*"
        "Remote Utilities (Dir 4)" = "$env_programdata\Remote Utilities*"
        "Remote Utilities (Dir 5)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\Remote Utilities Agent"
        "ScreenMeet (Dir 1)" = "$env_programdata\Projector Inc\ScreenMeet*"
        "ShowMyPC (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\Temp\ShowMyPC"
        "ShowMyPC (Dir 2)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\ShowMyPC"
        "SightCall" = ""
        "Surfly" = ""
        "Supremo (Dir 1)" = "$env_programdata\SupremoRemoteDesktop"
        "Syncro (Dir 1)" = "$env_programdata\Syncro"
        "Syncro (Dir 2)" = "$env_homedrive\Program Files\RepairTech\Syncro"
        "TightVNC (Log 1)" = "$env_homedrive\Windows\System32\config\systemprofile\AppData\Roaming\TightVNC\tvnserver.log"
        "TightVNC (Log 2)" = "$env_programdata\TightVNC\tvnserver.log"
        "TightVNC (Dir 1)" = "$env_programdata\TightVNC"
        "TeamViewer (Log 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\TeamViewer\Connections.txt"
        "TeamViewer (Log 2)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\Temp\TeamViewer\Connections_incoming.txt"
        "TeamViewer (Log 3)" = "$env_homedrive\Program Files\TeamViewer\Connections_incoming.txt"
        "TeamViewer (Log 4)" = "$env_homedrive\Program Files\TeamViewer\TeamViewer*_Logfile.log"
        "TeamViewer (Log 5)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\TeamViewer\Logs\TeamViewer*_Logfile.log"
        "TeamViewer (Log 6)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\TeamViewer\TeamViewer*_Logfile.log"
        "TeamViewer (Reg 1)" = "Registry::{0}SOFTWARE\TeamViewer" -f $regtarget_hklm
        "TeamViewer (Reg 2)" = "Registry::{0}SYSTEM\*\Services\TeamViewer" -f $regtarget_hklm
        #"TeamViewer (Reg 3)" = "Registry::{0}SYSTEM\ControlSet001\Services\TeamViewer" -f $regtarget_hklm
        "UltraVNC (Log 1)" = "$env_programdata\uvnc bvba\WinVNC.log"
        "UltraVNC (Log 2)" = "$env_programdata\uvnc bvba\mslogon.log"
        "UltraVNC (Dir 1)" = "$env_programdata\uvnc bvba"
        "UltraViewer (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Roaming\UltraViewer"
        "UltraViewer (Dir 2)" = "$env_homedrive\Program Files (x86)\Ultraviewer"
        "XMReality" = ""
        "Viewabo" = ""
        "XEOX (Dir 1)" = "$env_homedrive\Program Files\XEOX"
        "ZoHo Assist (Dir 1)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\ZohoMeeting"
        "ZoHo Assist (Dir 2)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\GoTo Resolve Applet"
        "ZoHo Assist (Dir 3)" = "$env_homedrive\Program Files (x86)\GoTo Resolve*"
        "ZoHo Assist (Dir 4)" = "$env_homedrive\Users\USER_REPLACE\AppData\Local\GoTo"
        "ZoHo Assist (Dir 5)" = "$env_programdata\ZohoMeeting"
    }
    if (Test-Path "$env_homedrive\Users")
    {
        $profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
    } else {
        $profile_names = @()
        Write-Warning "[!] Could not find '$env_homedrive\Users'!"
    }


    foreach ($item in $application_logpaths.GetEnumerator()){
        $paths = @()
        $checked_path = $item.Value
        $rat_name = $item.Name
        if ($checked_path -eq ""){
            continue
        }
        if ($profile_names.Count -ne 0){
            foreach ($user in $profile_names){
                if ($checked_path -match ".*USER_REPLACE.*"){
                    $tmp = $checked_path.Replace("USER_REPLACE", $user.Name)
                    $paths += $tmp
                } elseif ($checked_path -match ".*HKCU.*"){
                    foreach ($p in $regtarget_hkcu_list){
                        $paths += $checked_path.Replace("HKCU", $p)
                    }
                    break
                } else{
                    $paths += $checked_path
                    break
                }
            }
        } else {
            if ($checked_path -match ".*HKCU.*")
            {
                foreach ($p in $regtarget_hkcu_list)
                {
                    $paths += $checked_path.Replace("HKCU", $p)
                }
            } else {
                $paths += $checked_path
            }
        }
        foreach ($tmppath in $paths){
            if(Test-Path $tmppath){
                $detection = [PSCustomObject]@{
                    Name = 'Remote Access Tool Artifact'
                    Risk = 'Medium'
                    Source = 'Software'
                    Technique = "T1219: Remote Access Software"
                    Meta = [PSCustomObject]@{
                        RemoteAccessTool = $rat_name
                        Location = $tmppath
                    }
                }
                Write-Detection $detection
                #Write-Host "Found RAT Artifact: $rat_name, Location: $checked_path"
            }
        }
    }
}