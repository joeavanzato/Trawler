#region HelperMethods

function Write-Message ($message) {
    <#
    .SYNOPSIS
        Write-Host wrapper to standardize messages to the console
    #>
    # TODO - Message 'types' to alter the symbol as appropriate (detection, info, warning, error, etc)
    Write-Host "[+] $message"
}

function Test-OutputDirectoryPermissions() {
    <#
    .SYNOPSIS
        Validates output directory exists and that current user has appropriate permissions to write files
    #>
    # if the output path doesn't exist, create it.
    if (!(Test-Path $OutputLocation)) {
        try {
            New-Item $OutputLocation -Type Directory
            return $true
        }
        catch {
            return $false
        }
    }
    else {
        # Can we write to the specified dir?
        $testfile = Join-Path $OutputLocation "trawler_writetest.trawler"
        Try {
            [io.file]::OpenWrite($testfile).close()
            Remove-Item $testfile
            return $true
        }
        Catch {
            return $false
        }
    }
}

function New-TrawlerOutputItem() {
    <#
    .SYNOPSIS
        Helper function to create output items and report on failures.
    #>
    param (
        [string]
        $FileName,
        [string]
        $FileType
    )
    $timestamp = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
    $output = [PSCustomObject]@{
        Path     = [System.IO.Path]::Combine($OutputLocation, "$($FileName)_$($timestamp).$($FileType.ToLower())")
        CanWrite = $false
    }
    #TODO - Review as this check should be unnecessary as we already validate write capabilities before this
    try {
        [System.IO.File]::OpenWrite($output.Path).Close()
        $output.CanWrite = $true
    }
    catch {
        Write-Warning "Unable to write to provided output path: $($output.Path)"
    }
    $output
}

function Write-Reportable-Issue($msg) {
    Write-Warning $msg
    Write-Warning "Please report this issue at https://github.com/joeavanzato/Trawler/issues"
}

function Get-File-Hash($file) {
    <#
    .SYNOPSIS
        Receives a path to a file as a string, validates the path exists and uses the globally-defined HashMode to return either an MD5, SHA1 or SHA256 hash.
    #>
    # Path
    # %SystemRoot%\system32 ([System.Environment]::SystemDirectory)
    # %SystemRoot%
    $file = $file.Trim()
    $file = $file.Trim("`"")
    $file = $file.Trim("\")
    $file = $file.Trim("?")
    $file = $file.Trim("\")

    if ($file -eq "") {
        return "Invalid File Path"
    }

    if ($file.StartsWith("system32")) {
        $file = $file -replace "system32", [System.Environment]::SystemDirectory
    }

    if ($file.Contains("<") -or $file.Contains(">") -or $file.Contains("`"") -or $file.Contains("/") -or $file.Contains("|") -or $file.Contains("?") -or $file.Contains("*")) {
        return "Invalid File Path"
    }


    $filepath = ""
    $filefound = $false
    if (Test-Path $file -PathType Leaf) {
        $filepath = $file
        $filefound = $true
    }
    elseif ($file.Contains(":")) {
        return "Invalid File Path"
    }
    elseif (Test-Path $(Join-Path -Path ([System.Environment]::SystemDirectory) -ChildPath $file) -PathType Leaf) {
        # check if in system32
        $filepath = $(Join-Path -Path ([System.Environment]::SystemDirectory) -ChildPath $file)
        $filefound = $true
    }
    elseif (Test-Path $(Join-Path -Path ([Environment]::GetFolderPath("Windows")) -ChildPath $file) -PathType Leaf) {
        # check if in windows
        $filepath = $(Join-Path -Path ([Environment]::GetFolderPath("Windows")) -ChildPath $file)
        $filefound = $true
    }
    else {
        # Check all dirs in path to see if it exists
        $paths = $env:Path -split ";"
        foreach ($p in $paths) {
            $p = $p.Trim()
            if ($p -eq "") {
                continue
            }
            $test = $(Join-Path -Path $p -ChildPath $file)
            if (Test-Path $test -PathType Leaf) {
                $filepath = $test
                $filefound = $true
                break
            }
        }
    }

    if (-not $filefound) {
        return "File Not Found"
    }

    try {
        # Couldn't find initial
        $hash = Get-FileHash -Algorithm $HashMode -Path $file
        return $hash.Hash
    }
    catch {
        return "Access Error"
    }
    return "Hashing Error"
}

function Format-MetadataToString($detectionmeta) {
    <#
    .SYNOPSIS
        Receives an object representing the metadata of a specific detection and formats this to a more human-readable string for u se in CSV/Console output
    #>
    $output = ""
    $propertyCount = ($detectionmeta | Get-Member -Type NoteProperty).count
    $index = 1
    foreach ($prop in $detectionmeta.PSObject.Properties) {
        if ($index -eq $propertyCount) {
            $output += "$($prop.Name): $($prop.Value)"
        }
        else {
            $output += "$($prop.Name): $($prop.Value), "
        }
        $index += 1
    }
    return $output
}

function Get-HashOfString($string) {
    <#
    .SYNOPSIS
        Receives a string and converts it to a hash-representation, emitting the resulting hash
    #>
    $stream = [System.IO.MemoryStream]::new()
    $w = [System.IO.StreamWriter]::new($stream)
    $w.write($string)
    $w.Flush()
    $stream.Position = 0
    $hash = Get-FileHash -Algorithm SHA1 -InputStream $stream
    return $hash.Hash
}

function Format-DateTime($datetime, $utc_convert) {
    <#
    .SYNOPSIS
        Receives a PowerShell datetime object and a boolean - returns a standardized string representation - if utc_convert is $true, converts the (assumed) local timestamp into UTC
    #>
    if ($utc_convert) {
        return $datetime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss")
    }
    else {
        return $datetime.ToString("yyyy-MM-dd'T'HH:mm:ss")
    }
}

#endregion