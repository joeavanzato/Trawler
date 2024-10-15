function Check-Users {
    # Can possibly support drive retargeting by reading SAM/SYSTEM Hives if intact
    # https://habr.com/en/articles/441410/
    if ($drivechange){
        Write-Message "Skipping User Analysis - No Drive Retargeting [yet]"
        return
    }

    Write-Message "Checking Local Administrators"

    # TODO - Catch error with outdated powershell versions that do not support Get-LocalGroupMember and use alternative gather mechanism
    # Find all local administrators and their last logon time as well as if they are enabled.
    $local_admins = Get-LocalGroupMember -Group "Administrators" | Select-Object *

    foreach ($admin in $local_admins){
        $admin_user = Get-LocalUser -SID $admin.SID | Select-Object AccountExpires,Description,Enabled,FullName,PasswordExpires,UserMayChangePassword,PasswordLastSet,LastLogon,Name,SID,PrincipalSource

        $detection = [PSCustomObject]@{
            Name = 'Local Administrator Account'
            Risk = 'Medium'
            Source = 'Users'
            Technique = "T1136: Create Account"
            Meta = [PSCustomObject]@{
                User = $admin.Name
                LastLogon = $admin_user.LastLogon
                Enabled = $admin_user.Enabled
            }
        }
        Write-Detection $detection
    }
    
}