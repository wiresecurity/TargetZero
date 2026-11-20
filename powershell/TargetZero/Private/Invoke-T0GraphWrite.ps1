# SPDX-License-Identifier: Apache-2.0
function Invoke-T0GraphWrite {
    <#
    .SYNOPSIS
        POST, PATCH or DELETE to Microsoft Graph. Used only by change commands, after their own
        dry-run and ShouldProcess checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('POST', 'PATCH', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Body,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0'
    )
    $url = "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))"
    $parameters = @{ Method = $Method; Uri = $url; OutputType = 'Hashtable' }
    if ($Body) {
        $parameters['Body'] = ConvertTo-Json -InputObject $Body -Depth 10
        $parameters['ContentType'] = 'application/json'
    }
    # Stop on errors, so a failed change is never reported as applied.
    Invoke-MgGraphRequest @parameters -ErrorAction Stop
}
