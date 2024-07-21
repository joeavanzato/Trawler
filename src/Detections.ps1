function Write-Detection($det) {
	# det is a custom object which will contain various pieces of metadata for the detection
	# Name - The name of the detection logic.
	# Risk (Very Low, Low, Medium, High, Very High)
	# Source - The source 'module' reporting the detection
	# Technique - The most relevant MITRE Technique
	# Meta - String containing reference material specific to the received detection
	$detection_list.Add($det) | Out-Null

	switch ($det.Risk) {
		"Very Low" { $fg_color = "Green" }
		"Low" { $fg_color = "Green" }
		"Medium" { $fg_color = "Yellow" }
		"High" { $fg_color = "Red" }
		"Very High" { $fg_color = "Magenta" }
		Default { $fg_color = "Yellow" }
	}

	if (-not($Quiet)) {
		Write-Host "[!] Detection: $($det.Name) - Risk: $($det.Risk)" -ForegroundColor $fg_color
		Write-Host "[%] $($det.Meta)" -ForegroundColor White
	}

	if ($output_writable) {
		$det | Export-CSV $outpath -Append -NoTypeInformation -Encoding UTF8
	}
}

function Get-TrawlerDetectionMetrics {
	Write-Host "[!] ### Detection Metadata ###" -ForeGroundColor White
	Write-Message "Total Detections: $($detection_list.Count)"

	foreach ($str in ($detection_list | Group-Object Risk | Select-Object Name, Count | Out-String).Split([System.Environment]::NewLine)) {
		if (-not ([System.String]::IsNullOrWhiteSpace($str))){
			Write-Message $str
		}
	}
}