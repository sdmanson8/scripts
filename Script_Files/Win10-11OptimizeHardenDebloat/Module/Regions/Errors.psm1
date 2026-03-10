using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Errors
<#
	.SYNOPSIS
	Log the collected script errors and show the final log file location.

	.DESCRIPTION
	Filters the accumulated PowerShell error list, formats the remaining errors
	with file and line information, writes them to the Win10_11Util log, and
	then shows the user where the log file was saved.

	.EXAMPLE
	Errors
#>
function Errors
{
    if ($Global:Error)
    {
        $FilteredErrors = $Global:Error | Where-Object {
            $_.Exception.Message -notmatch 'Property .* does not exist|Cannot find path|Cannot find a process with the name|The process ".*" not found|The operation completed successfully\.|The system was unable to find the specified registry key or value\.|The registry key at the specified path does not exist\.|Cannot find any service with service name|No package found for ''Microsoft Edge|No MSFT_ScheduledTask objects found with property ''TaskName'' equal to ''Disable LockScreen''|A key in this path already exists\.'
        }

        if ($FilteredErrors)
        {
            $ErrorOutput = $FilteredErrors | ForEach-Object {
                $ErrorInFile = if ($_.InvocationInfo.PSCommandPath) {
                    Split-Path -Path $_.InvocationInfo.PSCommandPath -Leaf
                }

                [PSCustomObject]@{
                    Line    = $_.InvocationInfo.ScriptLineNumber
                    File    = $ErrorInFile
                    Message = $_.Exception.Message
                }
            } | Sort-Object Line | Format-Table -AutoSize -Wrap | Out-String

            LogError $ErrorOutput.Trim()
        }
    }

    LogInfo "Script is finished"
    Write-Host "Script is finished, log file can be found here '$Global:LogFilePath'" -ForegroundColor DarkYellow
    Write-Warning "Please restart your computer to ensure all changes are fully applied."
    Read-Host "Press Enter to close"
}
#endregion Errors
