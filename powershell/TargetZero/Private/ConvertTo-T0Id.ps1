# SPDX-License-Identifier: Apache-2.0
function ConvertTo-T0Id {
    <#
    .SYNOPSIS
        Builds a stable item id: <source>:<part>/<part>, lowercase, no spaces or semicolons.
        Same rules as targetzero.common.ids.make_id in Python.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][AllowEmptyString()][string[]]$Part
    )
    $clean = foreach ($p in $Part) {
        if ($p -and $p.Trim()) {
            ($p.Trim().ToLowerInvariant() -replace '[\s;]+', '-').Trim('-')
        }
    }
    return "$($Source):$(@($clean) -join '/')"
}
