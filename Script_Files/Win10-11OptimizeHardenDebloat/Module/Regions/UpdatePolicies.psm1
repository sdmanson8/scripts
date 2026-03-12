using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Update Policies
<#
	.SYNOPSIS
	Display all policy registry keys (even manually created ones) in the Local Group Policy Editor snap-in (gpedit.msc)
	This can take up to 30 minutes, depending on the number of policies created in the registry and your system resources

	.EXAMPLE
	UpdateLGPEPolicies

	.NOTES
	https://techcommunity.microsoft.com/t5/microsoft-security-baselines/lgpo-exe-local-group-policy-object-utility-v1-0/ba-p/701045

	.NOTES
	Machine-wide user
	Current user
#>
function UpdateLGPEPolicies
{
	if (-not (Test-Path -Path "$env:SystemRoot\System32\gpedit.msc"))
	{
		LogWarning ($Localization.Skipped -f $MyInvocation.Line.Trim())

		return
	}

	Get-Partition | Where-Object -FilterScript {$_.DriveLetter -eq $([System.Environment]::ExpandEnvironmentVariables($env:SystemDrive).Replace(":", ""))} | Get-Disk | Get-PhysicalDisk | ForEach-Object -Process {
	}

	# Local Machine policies paths to scan recursively
	$LM_Paths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
		"HKLM:\SOFTWARE\Policies\Microsoft"
	)
	foreach ($Path in (@(Get-ChildItem -Path $LM_Paths -Recurse -Force -ErrorAction Ignore)))
	{
		foreach ($Item in $Path.Property)
		{
			# Checking whether property isn't equal to "(default)" and exists
			if (($null -ne $Item) -and ($Item -ne "(default)"))
			{
				# Where all ADMX templates are located to compare with
				foreach ($admx in @(Get-ChildItem -Path "$env:SystemRoot\PolicyDefinitions" -File -Force))
				{
					# Parse every ADMX template searching if it contains full path and registry key simultaneously
					[xml]$config = Get-Content -Path $admx.FullName -Encoding UTF8
					$config.SelectNodes("//@*") | ForEach-Object -Process {$_.value = $_.value.ToLower()}
					$SplitPath = $Path.Name.Replace("HKEY_LOCAL_MACHINE\", "")

					if ($config.SelectSingleNode("//*[local-name()='policy' and @key='$($SplitPath.ToLower())' and (@valueName='$($Item.ToLower())' or @Name='$($Item.ToLower())' or .//*[local-name()='enum' and @valueName='$($Item.ToLower())'])]"))
					{
						$Type = switch ((Get-Item -Path $Path.PSPath).GetValueKind($Item))
						{
							"DWord"
							{
								(Get-Item -Path $Path.PSPath).GetValueKind($Item).ToString().ToUpper()
							}
							"ExpandString"
							{
								"EXSZ"
							}
							"String"
							{
								"SZ"
							}
						}

						$Parameters = @{
							Scope = "Computer"
							# e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
							Path  = $Path.Name.Replace("HKEY_LOCAL_MACHINE\", "")
							Name  = $Item.Replace("{}", "")
							Type  = $Type
							Value = Get-ItemPropertyValue -Path $Path.PSPath -Name $Item
						}
						Set-Policy @Parameters
					}
				}
			}
		}
	}

	# Current User policies paths to scan recursively
	$CU_Paths = @(
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies",
		"HKCU:\Software\Policies\Microsoft"
	)
	foreach ($Path in (@(Get-ChildItem -Path $CU_Paths -Recurse -Force)))
	{
		foreach ($Item in $Path.Property)
		{
			# Checking whether property isn't equal to "(default)" and exists
			if (($null -ne $Item) -and ($Item -ne "(default)"))
			{
				# Where all ADMX templates are located to compare with
				foreach ($admx in @(Get-ChildItem -Path "$env:SystemRoot\PolicyDefinitions" -File -Force))
				{
					# Parse every ADMX template searching if it contains full path and registry key simultaneously
					[xml]$config = Get-Content -Path $admx.FullName -Encoding UTF8
					$config.SelectNodes("//@*") | ForEach-Object -Process {$_.value = $_.value.ToLower()}
					$SplitPath = $Path.Name.Replace("HKEY_CURRENT_USER\", "")

					if ($config.SelectSingleNode("//*[local-name()='policy' and @key='$($SplitPath.ToLower())' and (@valueName='$($Item.ToLower())' or @Name='$($Item.ToLower())' or .//*[local-name()='enum' and @valueName='$($Item.ToLower())'])]"))
					{
						$Type = switch ((Get-Item -Path $Path.PSPath).GetValueKind($Item))
						{
							"DWord"
							{
								(Get-Item -Path $Path.PSPath).GetValueKind($Item).ToString().ToUpper()
							}
							"ExpandString"
							{
								"EXSZ"
							}
							"String"
							{
								"SZ"
							}
						}

						$Parameters = @{
							Scope = "User"
							# e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
							Path  = $Path.Name.Replace("HKEY_CURRENT_USER\", "")
							Name  = $Item.Replace("{}", "")
							Type  = $Type
							Value = Get-ItemPropertyValue -Path $Path.PSPath -Name $Item
						}
						Set-Policy @Parameters
					}
				}
			}
		}
	}

	# Run gpupdate silently
	cmd /c "gpupdate /force > NUL 2>&1"
}

<#
	.SYNOPSIS
	Scan the Windows registry and display all policies (even created manually) in the Local Group Policy Editor snap-in (gpedit.msc)

	.EXAMPLE
	ScanRegistryPolicies

	.NOTES
	https://techcommunity.microsoft.com/t5/microsoft-security-baselines/lgpo-exe-local-group-policy-object-utility-v1-0/ba-p/701045

	.NOTES
	Machine-wide user
	Current user
#>
function ScanRegistryPolicies
{
	Write-ConsoleStatus -Action "Scanning registry for policies to display in the Local Group Policy Editor snap-in"
	LogInfo "Scanning registry for policies to display in the Local Group Policy Editor snap-in"
	if (-not (Test-Path -Path "$env:SystemRoot\System32\gpedit.msc"))
	{
		LogWarning ($Localization.gpeditNotSupported, ($Localization.Skipped -f $MyInvocation.Line.Trim()) -join " ")

		return
	}

	# Policy paths to scan recursively
	$PolicyKeys = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
		"HKLM:\SOFTWARE\Policies\Microsoft",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies",
		"HKCU:\Software\Policies\Microsoft"
	)
	foreach ($Path in (@(Get-ChildItem -Path $PolicyKeys -Recurse -Force -ErrorAction Ignore)))
	{
		foreach ($Item in $Path.Property)
		{
			# Checking whether property isn't equal to "(default)" and exists
			if (($null -ne $Item) -and ($Item -ne "(default)"))
			{
				# Where all ADMX templates are located to compare with
				foreach ($admx in @(Get-ChildItem -Path "$env:SystemRoot\PolicyDefinitions" -File -Filter *.admx -Force))
				{
					# Parse every ADMX template searching if it contains full path and registry key simultaneously
					# No -Force argument
					[xml]$admxtemplate = Get-Content -Path $admx.FullName -Encoding UTF8
					$SplitPath = $Path.Name.Replace("HKEY_LOCAL_MACHINE\", "").Replace("HKEY_CURRENT_USER\", "")

					if ($admxtemplate.policyDefinitions.policies.policy | Where-Object -FilterScript {($_.key -eq $SplitPath) -and (($_.valueName -eq $Item) -or ($_.Name -eq $Item))})
					{
						#Write-Verbose -Message ([string]($Path.Name, "|", $Item.Replace("{}", ""), "|", $(Get-ItemPropertyValue -Path $Path.PSPath -Name $Item))) -Verbose

						$Type = switch ((Get-Item -Path $Path.PSPath).GetValueKind($Item))
						{
							"DWord"
							{
								(Get-Item -Path $Path.PSPath).GetValueKind($Item).ToString().ToUpper()
							}
							"ExpandString"
							{
								"EXSZ"
							}
							"String"
							{
								"SZ"
							}
						}

						$Scope = if ($Path.Name -match "HKEY_LOCAL_MACHINE")
						{
							"Computer"
						}
						else
						{
							"User"
						}

						$Parameters = @{
							# e.g. User
							Scope = $Scope
							# e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
							Path  = $Path.Name.Replace("HKEY_LOCAL_MACHINE\", "").Replace("HKEY_CURRENT_USER\", "")
							# e.g. NoUseStoreOpenWith
							Name  = $Item.Replace("{}", "")
							# e.g. DWORD
							Type  = $Type
							# e.g. 1
							Value = Get-ItemPropertyValue -Path $Path.PSPath -Name $Item
						}
						Set-Policy @Parameters
					}
				}
			}
		}
	}
	Write-ConsoleStatus -Status success
}
#endregion Update Policies
