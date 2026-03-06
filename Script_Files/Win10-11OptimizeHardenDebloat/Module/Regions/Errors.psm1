using module ..\Logging.psm1
using module ..\Helpers.psm1

#region Errors
function Errors
{
    if ($Global:Error)
    {
        $FilteredErrors = $Global:Error | Where-Object {
            $_.Exception.Message -notmatch 'Property .* does not exist|Cannot find path'
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
    Pause
}
#endregion Errors
