# SPDX-License-Identifier: Apache-2.0
function Get-T0M365Domain {
    <#
    .SYNOPSIS
        Writes the tenant's domains to 5_m365_domains.csv, a seed for `targetzero external discover`.
    .EXAMPLE
        Get-T0M365Domain -Config (Import-T0Config)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [datetime]$RunDate = (Get-Date)
    )
    $rows = foreach ($domain in (Invoke-T0Graph -Uri 'domains?$select=id,isVerified,isDefault,authenticationType' -All)) {
        [pscustomobject]@{
            domain   = ([string]$domain['id']).ToLowerInvariant()
            verified = if ($domain['isVerified']) { 'Y' } else { 'N' }
            primary  = if ($domain['isDefault']) { 'Y' } else { 'N' }
            kind     = ([string]$domain['authenticationType']).ToLowerInvariant()
        }
    }
    $dir = Get-T0RunDirectory -Config $Config -RunDate $RunDate
    Export-T0Record -RunDirectory $dir -Zero 5 -Source m365 -Name domains -Records @($rows) -Property domain, verified, primary, kind
}
