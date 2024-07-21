function Test-MatchIPv4Address {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Value
    )

    return $Value -match $TrawlerIPv4Pattern
}

function Test-MatchIPv6Address {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Value
    )

    return $Value -match $TrawlerIPv6Pattern
}

function Test-MatchIPAddress {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Value
    )

    return Test-MatchIPv4Address -Value $Value -or Test-MatchIPv6Address -Value $Value
}

function Test-TrawlerOfficeExtension {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Value
    )

    return $Value -in $TrawlerOfficeAddInExtensions
}

function Test-RemoteAccessTrojanTerms {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Values
    )

    if ($TrawlerRATTerms.Contains($Value)) {
        return $true
    }

    foreach ($term in $TrawlerRATTerms) {
        foreach ($Value in $Values) {
            if ($Value -match ".*$term.*") {
                return $true
            }
        }
    }

    return $false
}

function Test-SuspiciousProcessPaths {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Value
    )

    $Value = ($Value | Out-String).Trim()

    foreach ($path in $TrawlerSuspiciousProcessPaths) {
        if ($Value -match $path) {
            return $true
        }
    }

    return $false
}

function Test-TrawlerSuspiciousPorts {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Values
    )

    foreach ($value in $values) {
        foreach ($port in $TrawlerSuspiciousPorts) {
            if ($value -eq $port) {
                return $true
            }
        }
    }

    return $false
}

function Test-TrawlerSuspiciousTerms {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Values
    )

    foreach ($value in $values) {
        if ($value -match $TrawlerSuspiciousTerms) {
            return $true
        }
    }

    return $false
}

$TrawlerSuspiciousPorts = @(20, 21, 22, 23, 25, 137, 139, 445, 3389, 443)

$TrawlerIPv4Pattern = '.*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*'
$TrawlerIPv6Pattern = '.*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*'
$TrawlerSuspiciousTerms = ".*(\[System\.Reflection\.Assembly\]|regedit|invoke-iex|frombase64|tobase64|rundll32|http:|https:|system\.net\.webclient|downloadfile|downloadstring|bitstransfer|system\.net\.sockets|tcpclient|xmlhttp|AssemblyBuilderAccess|shellcode|rc4bytestream|disablerealtimemonitoring|wmiobject|wmimethod|remotewmi|wmic|gzipstream|::decompress|io\.compression|write-zip|encodedcommand|wscript\.shell|MSXML2\.XMLHTTP).*"
$TrawlerOfficeAddInExtensions = @(".wll", ".xll", ".ppam", ".ppa", ".dll", ".vsto", ".vba", ".xlam", ".com", ".xla")

$TrawlerRATTerms = @(
    # Remote Access Tool Indicators
    # Any Process Name, Scheduled Task or Service containing these keywords will be flagged.
    "aeroadmin",
    "action1"
    "ammyadmin"
    "aa_v"
    "anydesk"
    "anyscreen"
    "anyviewer"
    "atera"
    "aweray_remote"
    "awrem32"
    "awhost32"
    "beyondtrust"
    "bomgar"
    "connectwise"
    "cservice"
    "dameware"
    "desktopnow"
    "distant-desktop"
    "dwservice"
    "dwagent"
    "dwagsvc"
    "dwrcs"
    "famitrfc"
    "g2comm"
    "g2host"
    "g2fileh"
    "g2mainh"
    "g2printh"
    "g2svc"
    "g2tray"
    "gopcsrv"
    "getscreen"
    "iperius"
    "kaseya"
    "litemanager"
    "logmein"
    "lmiignition"
    "lmiguardiansvc"
    "meshagent"
    "mstsc"
    "ninja1"
    "ninjaone"
    "PCMonitorManager"
    "pcmonitorsrv"
    "pulseway"
    "quickassist"
    "radmin"
    "rcclient"
    "realvnc"
    "remotepc"
    "remotetopc"
    "remote utilities"
    "RepairTech"
    "ROMServer"
    "ROMFUSClient"
    "rutserv"
    "screenconnect"
    "screenmeet"
    "showmypc"
    "smpcsetup"
    "strwinclt"
    "supremo"
    "sightcall"
    "splashtop"
    "surfly"
    "syncro"
    "tacticalrmm"
    "teamviewer"
    "tightvnc"
    "ultraviewer"
    "vnc"
    "winvnc"
    "vncviewer"
    "winvncsc"
    "winwvc"
    "xmreality"
    "ultravnc"
    "Zaservice"
    "Zohours"
    "ZohoMeeting"
    "zoho"
)

$TrawlerSuspiciousProcessPaths = @(
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