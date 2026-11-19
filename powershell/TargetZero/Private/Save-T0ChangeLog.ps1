# SPDX-License-Identifier: Apache-2.0
function Save-T0ChangeLog {
    <#
    .SYNOPSIS
        Writes what a change command did (JSON) and how to undo it (a plan CSV with rollback actions).
    .DESCRIPTION
        changes_<name>_<timestamp>.json   every planned action with status, before and after
        rollback_<name>_<timestamp>.csv   a plan that the same command can apply to undo the changes
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Change,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rollback,
        [Parameter(Mandatory)][string[]]$Property,
        [switch]$DryRun
    )
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
    $prefix = if ($DryRun) { 'dryrun' } else { 'changes' }
    $log = Join-Path $RunDirectory "$($prefix)_$($Name)_$stamp.json"
    $context = if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { Get-MgContext } else { $null }
    $account = if ($context) { $context.Account } else { '' }
    $document = [ordered]@{
        tool      = $Name
        dry_run   = [bool]$DryRun
        timestamp = [datetime]::UtcNow.ToString('o', [cultureinfo]::InvariantCulture)
        account   = $account
        changes   = @($Change)
    }
    Set-Content -LiteralPath $log -Value (ConvertTo-Json -InputObject $document -Depth 10) -Encoding utf8NoBOM
    $paths = @($log)
    if (-not $DryRun -and $Rollback.Count) {
        $rollbackPath = Join-Path $RunDirectory "rollback_$($Name)_$stamp.csv"
        $Rollback | ForEach-Object { [pscustomobject]$_ } | Select-Object -Property $Property |
            Export-Csv -LiteralPath $rollbackPath -NoTypeInformation -Encoding utf8NoBOM -UseQuotes AsNeeded
        $paths += $rollbackPath
    }
    return $paths
}
