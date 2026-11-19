# SPDX-License-Identifier: Apache-2.0
function Get-T0RunDirectory {
    <#
    .SYNOPSIS
        Returns (and creates) the output folder for a run date: <output_dir>/<yyyy-MM-dd>.
    .EXAMPLE
        $dir = Get-T0RunDirectory -Config (Import-T0Config)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [datetime]$RunDate = (Get-Date)
    )
    $path = Join-Path $Config.OutputDirectory $RunDate.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    $null = New-Item -ItemType Directory -Path $path -Force
    return $path
}
