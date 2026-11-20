# SPDX-License-Identifier: Apache-2.0
function Get-T0GraphError {
    <#
    .SYNOPSIS
        Short text for a failed Graph call, "code: message", without the response headers
        that Invoke-MgGraphRequest puts in its error message.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $details = if ($ErrorRecord.ErrorDetails) { $ErrorRecord.ErrorDetails.Message } else { '' }
    $text = "$details $($ErrorRecord.Exception.Message)"
    if ($text -match '"code"\s*:\s*"([^"]+)"\s*,\s*"message"\s*:\s*"([^"]*)"') { return "$($Matches[1]): $($Matches[2])" }
    return @($ErrorRecord.Exception.Message -split '\r?\n')[0]
}
