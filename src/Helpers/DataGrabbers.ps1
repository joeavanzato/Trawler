function Get-TrawlerItemData {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]
		$Path,
		[Parameter(Mandatory)]
		[ValidateSet("Item", "ChildItem", "ItemProperty")]
		$ItemType,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	switch ($ItemType) {
		"Item" {
			return (Get-Item -Path $Path).PSObject.Properties
		}
		"ChildItem" {
			return (Get-ChildItem -Path $Path).PSObject.Properties
		}
		"ItemProperty" {
			return (Get-ItemProperty -Path $Path).PSObject.Properties
		}
	}
}

function Get-TrawlerChildItem {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	return Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
}

function Get-TrawlerItem {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	return Get-Item -Path $Path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
}

function Get-TrawlerItemObjectProperties {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	return (Get-Item -Path $Path).PSObject.Properties
}

function Get-TrawlerItemProperty {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	return Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
}

function Get-TrawlerItemPropertyObjectProperties {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		return (Get-TrawlerItemProperty -Path $path -AsRegistry).PSObject.Properties
	}
	else {
		return (Get-TrawlerItemProperty -Path $path).PSObject.Properties
	}
}

function Test-TrawlerPath {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]
		$Path,
		[Parameter()]
		[switch]
		$AsRegistry
	)

	if ($AsRegistry) {
		$Path = "Registry::$Path"
	}

	return Test-Path -Path $Path
}