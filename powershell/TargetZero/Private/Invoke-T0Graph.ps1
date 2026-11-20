# SPDX-License-Identifier: Apache-2.0
function Invoke-T0Graph {
    <#
    .SYNOPSIS
        GET request to Microsoft Graph, following @odata.nextLink when -All is set.
        Results are hashtables. Only Microsoft.Graph.Authentication is needed.
        Errors stop the caller: Invoke-MgGraphRequest reports them as non-terminating by default,
        which would let a script continue with an empty result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$All,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0'
    )
    $url = if ($Uri -like 'https://*') { $Uri } else { "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))" }
    $response = Invoke-MgGraphRequest -Method GET -Uri $url -OutputType Hashtable -ErrorAction Stop
    if (-not $All) { return $response }

    $items = [System.Collections.Generic.List[object]]::new()
    while ($true) {
        if ($response.ContainsKey('value')) {
            foreach ($value in $response['value']) { $items.Add($value) }
        }
        $next = $response['@odata.nextLink']
        if (-not $next) { break }
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
    }
    # Emit items one by one so callers can pipe them; wrap calls in @() when a list is needed.
    return $items.ToArray()
}
