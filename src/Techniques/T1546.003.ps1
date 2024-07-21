function Search-WMIConsumers {
	# Supports Dynamic Snapshotting
	# Drive Retargeting..maybe
	# https://netsecninja.github.io/dfir-notes/wmi-forensics/
	# https://github.com/davidpany/WMI_Forensics
	# https://github.com/mandiant/flare-wmi/blob/master/WMIParser/WMIParser/ActiveScriptConsumer.cpp
	# This would require building a binary parser in PowerShell..difficult.
	if ($drivechange){
		Write-Message "Skipping WMI Analysis - No Drive Retargeting [yet]"
		return
	}
	Write-Message "Checking WMI Consumers"
	$consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object *

	foreach ($consumer in $consumers) {
		if ($loadsnapshot){
			if ($consumer.CommandLineTemplate -ne $null){
				$val_ = $consumer.CommandLineTemplate
			} elseif ($consumer.ScriptFileName -ne $null) {
				$val_ = $consumer.ScriptFileName
			}
			$detection = [PSCustomObject]@{
				Name = 'Allowlist Mismatch:  WMI Consumer'
				Risk = 'Medium'
				Source = 'Services'
				Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
				Meta = "Consumer Name: "+ $consumer.Name+", Consumer Value: "+ $val_
			}
			$result = Confirm-IfAllowed $allowtable_wmi_consumers $consumer.Name $val_ $detection
			if ($result){
				continue
			}
		}
		if ($consumer.ScriptingEngine -ne $null) {
			Write-SnapshotMessage -Key $consumer.Name -Value $consumer.ScriptFileName -Source 'WMI Consumers'

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
			Write-SnapshotMessage -Key $consumer.Name -Value $consumer.CommandLineTemplate -Source 'WMI Consumers'
			
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