# SPDX-License-Identifier: Apache-2.0
function Export-T0AdminSummary {
    <#
    .SYNOPSIS
        Writes 1_<source>_admins.csv plus the Zero 1 and Zero 2 summaries from unified admin records.
    .DESCRIPTION
        Counts are per account, with the same rules as targetzero.admins in Python:
        - Zero 1: the account holds a privileged role permanently and is not a break-glass account.
        - Zero 2: the account is not a service account and has no MFA that counts
          (none, does-not-count, unknown) or MFA is not enforced for it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]*$')][string]$Source,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][string]$Tool,
        [datetime]$RunDate = (Get-Date),
        [bool]$Complete = $true,
        [string[]]$Notes = @()
    )
    $fields = 'id', 'source', 'system', 'account', 'role', 'account_type', 'privileged', 'permanent',
    'end_date', 'mfa_class', 'mfa_enforced', 'separate_admin_account', 'break_glass',
    'last_logon', 'last_verified', 'notes'
    $rank = @{ 'none' = 0; 'does-not-count' = 1; 'unknown' = 2; 'mfa' = 3; 'phishing-resistant' = 4 }
    $enforcedRank = @{ 'N' = 0; 'unknown' = 1; 'Y' = 2 }

    $rows = @($Records | ForEach-Object {
            $record = $_
            $row = [ordered]@{}
            foreach ($f in $fields) {
                $value = if ($record -is [System.Collections.IDictionary]) { $record[$f] }
                elseif ($record.PSObject.Properties[$f]) { $record.PSObject.Properties[$f].Value }
                else { $null }
                $row[$f] = if ($null -eq $value) { '' } else { [string]$value }
            }
            [pscustomobject]$row
        })

    $zero1 = [System.Collections.Generic.List[object]]::new()
    $zero2 = [System.Collections.Generic.List[object]]::new()
    $accounts = $rows | Group-Object { ConvertTo-T0Id -Source $_.source -Part $_.system, $_.account } | Sort-Object Name -CaseSensitive
    foreach ($account in $accounts) {
        $group = @($account.Group)
        $permanent = @($group | Where-Object { $_.privileged -eq 'Y' -and $_.permanent -eq 'Y' } | ForEach-Object role | Sort-Object -Unique -CaseSensitive)
        if ($permanent.Count -and -not ($group | Where-Object break_glass -EQ 'Y')) {
            $zero1.Add(@{ id = $account.Name; reason = 'Permanent ' + ($permanent -join ', ') })
        }
        if (@($group | Where-Object account_type -NE 'service').Count -eq 0) { continue }
        $mfa = $group.mfa_class | Sort-Object { if ($rank.ContainsKey($_)) { $rank[$_] } else { 0 } } | Select-Object -First 1
        $enforced = $group.mfa_enforced | Sort-Object { if ($enforcedRank.ContainsKey($_)) { $enforcedRank[$_] } else { 0 } } | Select-Object -First 1
        $mfaRank = if ($rank.ContainsKey($mfa)) { $rank[$mfa] } else { 0 }
        if ($mfaRank -lt $rank['mfa'] -or $enforced -ne 'Y') {
            $zero2.Add(@{ id = $account.Name; reason = "MFA: $mfa; enforced: $enforced" })
        }
    }

    $csv = Export-T0Record -RunDirectory $RunDirectory -Zero 1 -Source $Source -Name admins -Records $rows -Property $fields
    $recordFile = Split-Path -Leaf $csv
    $common = @{ RunDirectory = $RunDirectory; Source = $Source; Tool = $Tool; RunDate = $RunDate; Complete = $Complete; Notes = $Notes; RecordFile = $recordFile }
    return @(
        $csv
        Export-T0Summary @common -Zero 1 -Name admins -Items $zero1.ToArray()
        Export-T0Summary @common -Zero 2 -Name mfa -Items $zero2.ToArray()
    )
}
