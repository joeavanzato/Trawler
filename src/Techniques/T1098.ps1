function Check-RDPShadowConsent {
    # Supports Drive Retargeting
    Write-Message "Checking RDP Shadow Consent"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (Test-Path -Path $path) {
        $items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq 'Shadow' -and ($_.Value -eq 4 -or $_.Value -eq 2)) {
                $detection = [PSCustomObject]@{
                    Name = 'RDP Shadowing without Consent is Enabled'
                    Risk = 'High'
                    Source = 'Registry'
                    Technique = "T1098: Account Manipulation"
                    Meta = [PSCustomObject]@{
                        Location = $path
                        EntryName = $_.Name
                        EntryValue = $_.Value
                    }
                    Reference = "https://blog.bitsadmin.com/spying-on-users-using-rdp-shadowing"
                }
                Write-Detection $detection
            }
        }
    }
}

function Check-ServiceControlManagerSD {
    Write-Message "Checking Security Descriptor for Service Control Manager"
    # https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
    $default = 'D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)(A;;CC;;;S-1-15-3-1024-528118966-3876874398-709513571-1907873084-3598227634-3698730060-278077788-3990600205)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)'
    $current = (sc.exe sdshow scmanager) -join ''

    if ($default -ne $current)
    {
        $detection = [PSCustomObject]@{
            Name = 'Service Control Manager has non-default Security Descriptor'
            Risk = 'High'
            Source = 'Windows'
            Technique = "T1098: Account Manipulation"
            Meta = [PSCustomObject]@{
                EntryValue = $current
                ExpectedValue = $default
            }
            Reference = "https://pentestlab.blog/2023/03/20/persistence-service-control-manager"
        }
        Write-Detection $detection
    }
}