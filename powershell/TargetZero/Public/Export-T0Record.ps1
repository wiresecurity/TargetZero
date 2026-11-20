# SPDX-License-Identifier: Apache-2.0
function Export-T0Record {
    <#
    .SYNOPSIS
        Writes records to <zero>_<source>_<name>.csv in a run folder.
    .DESCRIPTION
        Columns follow -Property in that order, so the file always has a header, also when there
        are no records. Values are written as text; use Y/N for yes/no columns.
    .EXAMPLE
        Export-T0Record -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Records $rows -Property id, account, role
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][ValidateRange(1, 7)][int]$Zero,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]*$')][string]$Source,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]*$')][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_]+$')][string[]]$Property
    )
    $path = Join-Path $RunDirectory "$($Zero)_$($Source)_$($Name).csv"
    if ($Records.Count -eq 0) {
        Set-Content -LiteralPath $path -Value ($Property -join ',') -Encoding utf8NoBOM
    }
    else {
        $Records | Select-Object -Property $Property |
            Export-Csv -LiteralPath $path -Encoding utf8NoBOM -UseQuotes AsNeeded
    }
    return $path
}
