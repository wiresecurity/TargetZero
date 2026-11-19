# SPDX-License-Identifier: Apache-2.0
function Import-T0Csv {
    <#
    .SYNOPSIS
        Import-Csv that also reads files Excel saved with semicolons (Belgian, Dutch, French,
        German regional settings). Same rule as read_csv in Python.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    $header = Get-Content -LiteralPath $LiteralPath -TotalCount 1
    $delimiter = if (($header.Split(';').Count) -gt ($header.Split(',').Count)) { ';' } else { ',' }
    Import-Csv -LiteralPath $LiteralPath -Delimiter $delimiter
}
