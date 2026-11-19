# SPDX-License-Identifier: Apache-2.0
function Get-T0PrivilegedRole {
    <#
    .SYNOPSIS
        Reads a list from privileged_roles.yaml (the copy next to targetzero.yaml first).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [Parameter(Mandatory)][string]$Key
    )
    $candidates = @(
        (Join-Path (Split-Path -Parent $Config.Path) 'privileged_roles.yaml'),
        (Join-Path $script:ModuleRoot 'config' 'privileged_roles.yaml'),
        (Join-Path $script:ModuleRoot '..' '..' 'config' 'privileged_roles.yaml')
    )
    $file = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $file) { throw 'privileged_roles.yaml not found. Run targetzero init.' }
    $data = ConvertFrom-Yaml -Yaml (Get-Content -LiteralPath $file -Raw)
    if (-not $data.ContainsKey($Key)) { return @() }
    return @($data[$Key] | ForEach-Object { [string]$_ })
}
