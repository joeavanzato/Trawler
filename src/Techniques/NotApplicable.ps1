function Check-Suspicious-File-Locations {
    Write-Message "Checking Suspicious File Locations"
    $recursive_paths_to_check = @(
        "$env_homedrive\Users\Public"
        "$env_homedrive\Users\Administrator"
        "$env_homedrive\Users\Guest"
        "$env_homedrive\Windows\temp"
    )
    foreach ($path in $recursive_paths_to_check){
        $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Include $suspicious_extensions
        foreach ($item in $items){
            $detection = [PSCustomObject]@{
                Name = 'Anomalous File in Suspicious Location'
                Risk = 'High'
                Source = 'Windows'
                Technique = "N/A"
                Meta = [PSCustomObject]@{
                    Location = $item.FullName
                    Created = $item.CreationTime
                    Modified = $item.LastWriteTime
                    Hash = Get-File-Hash $item.FullName
                }
            }
            Write-Detection $detection
        }
    }
}