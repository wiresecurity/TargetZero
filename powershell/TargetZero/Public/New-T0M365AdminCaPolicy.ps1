# SPDX-License-Identifier: Apache-2.0
function New-T0M365AdminCaPolicy {
    <#
    .SYNOPSIS
        Creates the Target 0 Conditional Access policies for admins, in report-only mode first.
        Dry run unless -Apply.
    .DESCRIPTION
        Policies (the T0-BreakGlass group is excluded from both):
          T0 - Admins require phishing-resistant MFA   privileged roles from privileged_roles.yaml,
                                                       all apps, built-in "Phishing-resistant MFA" strength
          T0 - Block legacy authentication             all users, Exchange ActiveSync and other legacy clients

        Without -Enable the policies are created in report-only mode. Check their effect in
        Entra ID > Conditional Access > Insights and reporting, then run again with -Enable.

        -Enable refuses while any privileged admin in the latest admin inventory has no
        phishing-resistant method, because that admin would be locked out. -Force overrides.

        Without Entra ID P1 there is no Conditional Access. -UseSecurityDefaults then turns on
        Security Defaults instead (MFA for admins, legacy authentication blocked).

        Needs Connect-T0M365 -ReadWrite and the Conditional Access Administrator role.
    .EXAMPLE
        New-T0M365AdminCaPolicy -Config $config -Apply            # report-only
        New-T0M365AdminCaPolicy -Config $config -Apply -Enable    # enforce
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [switch]$Apply,
        [switch]$Enable,
        [switch]$UseSecurityDefaults,
        [switch]$Force,
        [datetime]$RunDate = (Get-Date)
    )
    $changes = [System.Collections.Generic.List[object]]::new()
    $plans = @(Invoke-T0Graph -Uri 'subscribedSkus' -All | Where-Object { $_['capabilityStatus'] -eq 'Enabled' } |
            ForEach-Object { $_['servicePlans'] } | ForEach-Object { $_['servicePlanName'] })
    $hasP1 = ($plans -contains 'AAD_PREMIUM') -or ($plans -contains 'AAD_PREMIUM_P2')
    $securityDefaults = (Invoke-T0Graph -Uri 'policies/identitySecurityDefaultsEnforcementPolicy')['isEnabled']
    $dir = Get-T0RunDirectory -Config $Config -RunDate $RunDate

    if (-not $hasP1) {
        $result = [ordered]@{ policy = 'Security Defaults'; action = 'enable'; status = ''; detail = '' }
        if ($securityDefaults) { $result.status = 'exists'; $result.detail = 'already on' }
        elseif (-not $UseSecurityDefaults) {
            $result.status = 'refused'
            $result.detail = 'No Entra ID P1, so no Conditional Access. Run again with -UseSecurityDefaults to turn on Security Defaults.'
        }
        elseif (-not $Apply) { $result.status = 'dry-run'; $result.detail = 'would turn on Security Defaults' }
        elseif ($PSCmdlet.ShouldProcess('tenant', 'turn on Security Defaults')) {
            Invoke-T0GraphWrite -Method PATCH -Uri 'policies/identitySecurityDefaultsEnforcementPolicy' -Body @{ isEnabled = $true } | Out-Null
            $result.status = 'applied'
        }
        $changes.Add($result); [pscustomobject]$result
        $null = Save-T0ChangeLog -RunDirectory $dir -Name 'm365_ca' -Change $changes.ToArray() -Rollback @() -Property policy -DryRun:(-not $Apply)
        return
    }
    if ($securityDefaults) {
        throw 'Security Defaults is on. Conditional Access policies cannot be created while it is on: turn it off in Entra ID > Properties first, and run this right after.'
    }

    $group = (Invoke-T0Graph -Uri "groups?`$filter=displayName eq 'T0-BreakGlass'&`$select=id" -All | Select-Object -First 1)
    if (-not $group) { throw 'Group T0-BreakGlass not found. Run New-T0M365BreakGlassAccount -Apply first.' }

    # Role template ids. The directory sync role is left out: that account cannot do MFA.
    $privileged = @(Get-T0PrivilegedRole -Config $Config -Key 'm365' | Where-Object { $_ -ne 'Directory Synchronization Accounts' })
    $templates = @(Invoke-T0Graph -Uri 'roleManagement/directory/roleDefinitions?$select=displayName,templateId' -All |
            Where-Object { $privileged -contains $_['displayName'] } | ForEach-Object { $_['templateId'] })

    $state = if ($Enable) { 'enabled' } else { 'enabledForReportingButNotEnforced' }
    $definitions = @(
        @{
            displayName   = 'T0 - Admins require phishing-resistant MFA'
            state         = $state
            conditions    = @{
                users          = @{ includeRoles = $templates; excludeGroups = @($group['id']) }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
        }
        @{
            displayName   = 'T0 - Block legacy authentication'
            state         = $state
            conditions    = @{
                users          = @{ includeUsers = @('All'); excludeGroups = @($group['id']) }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            grantControls = @{ operator = 'OR'; builtInControls = @('block') }
        }
    )

    # Lock-out check before enforcing the phishing-resistant policy.
    if ($Enable -and -not $Force) {
        $latest = Get-ChildItem -LiteralPath $Config.OutputDirectory -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName '1_m365_admins.csv' } |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $latest) { throw 'No admin inventory found. Run Invoke-T0M365AdminInventory first, or pass -Force.' }
        $atRisk = @(Import-T0Csv -LiteralPath $latest | Where-Object {
                $_.privileged -eq 'Y' -and $_.account_type -eq 'user' -and $_.break_glass -ne 'Y' -and $_.mfa_class -ne 'phishing-resistant'
            } | ForEach-Object account | Sort-Object -Unique)
        if ($atRisk) {
            throw "These admins have no phishing-resistant method and would be locked out: $($atRisk -join ', '). Register FIDO2 keys or passkeys first, run Invoke-T0M365AdminInventory again, or pass -Force. (Checked $latest)"
        }
    }

    $existing = @{}
    foreach ($p in (Invoke-T0Graph -Uri 'identity/conditionalAccess/policies?$select=id,displayName,state' -All)) { $existing[$p['displayName']] = $p }
    $rollback = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in $definitions) {
        $name = $definition.displayName
        $current = $existing[$name]
        $result = [ordered]@{ policy = $name; action = ''; status = ''; detail = '' }
        if ($current -and $current['state'] -eq $state) {
            $result.action = 'none'; $result.status = 'exists'; $result.detail = "already $state"
        }
        else {
            $result.action = if ($current) { "set state $state" } else { "create ($state)" }
            if (-not $Apply) { $result.status = 'dry-run'; $result.detail = "would $($result.action)" }
            elseif ($PSCmdlet.ShouldProcess($name, $result.action)) {
                try {
                    if ($current) {
                        Invoke-T0GraphWrite -Method PATCH -Uri "identity/conditionalAccess/policies/$($current['id'])" -Body @{ state = $state } | Out-Null
                        $rollback.Add(@{ policy_id = $current['id']; display_name = $name; restore_state = $current['state'] })
                    }
                    else {
                        $created = Invoke-T0GraphWrite -Method POST -Uri 'identity/conditionalAccess/policies' -Body $definition
                        $rollback.Add(@{ policy_id = $created['id']; display_name = $name; restore_state = 'delete' })
                    }
                    $result.status = 'applied'
                }
                catch { $result.status = 'failed'; $result.detail = Get-T0GraphError -ErrorRecord $_ }
            }
            else { $result.status = 'skipped'; $result.detail = 'not confirmed' }
        }
        $changes.Add($result); [pscustomobject]$result
    }
    $paths = Save-T0ChangeLog -RunDirectory $dir -Name 'm365_ca' -Change $changes.ToArray() -Rollback $rollback.ToArray() `
        -Property policy_id, display_name, restore_state -DryRun:(-not $Apply)
    Write-Information "Log: $($paths -join ', '). To undo: set the policy back to restore_state, or delete it, in Entra ID > Conditional Access." -InformationAction Continue
}
