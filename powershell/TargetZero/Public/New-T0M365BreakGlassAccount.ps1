# SPDX-License-Identifier: Apache-2.0
function New-T0M365BreakGlassAccount {
    <#
    .SYNOPSIS
        Creates the two emergency ("break-glass") Global Administrator accounts. Dry run unless -Apply.
    .DESCRIPTION
        For each account it creates a cloud-only user on the tenant's onmicrosoft.com domain, without
        a licence, with a 64-character random password; adds it to the group T0-BreakGlass (created
        when missing, used to exclude these accounts from Conditional Access); and assigns Global
        Administrator permanently.

        The passwords are shown ONCE in the output and never written to disk. Store them offline
        (printed, in a safe), then register a FIDO2 security key on each account.

        Account names come from break_glass.m365 in targetzero.yaml; without them,
        bg-admin-01 and bg-admin-02 are used. Existing accounts are left alone.

        Needs Connect-T0M365 -ReadWrite and the Global Administrator or Privileged Role Administrator
        plus User Administrator roles.
    .EXAMPLE
        New-T0M365BreakGlassAccount -Config $config -Apply
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [switch]$Apply,
        [datetime]$RunDate = (Get-Date)
    )
    $tenant = (Invoke-T0Graph -Uri 'organization?$select=id,verifiedDomains')['value'][0]
    $initial = @($tenant['verifiedDomains'] | Where-Object { $_['isInitial'] })[0]['name']
    $names = @($Config.BreakGlass['m365'] | Where-Object { $_ })
    if (-not $names.Count) {
        $names = @("bg-admin-01@$initial", "bg-admin-02@$initial")
        Write-Warning "break_glass.m365 is empty in targetzero.yaml. Using $($names -join ', '); add them to the config afterwards."
    }
    $elsewhere = @($names | Where-Object { $_ -notlike "*@$initial" })
    if ($elsewhere) {
        throw "Break-glass accounts must be on $initial, so they work when federation or custom domains fail: $($elsewhere -join ', ')"
    }

    $groupName = 'T0-BreakGlass'
    $group = (Invoke-T0Graph -Uri "groups?`$filter=displayName eq '$groupName'&`$select=id" -All | Select-Object -First 1)
    $changes = [System.Collections.Generic.List[object]]::new()
    if (-not $group) {
        $result = [ordered]@{ account = $groupName; action = 'create group'; status = 'dry-run'; detail = 'security group used to exclude break-glass accounts from Conditional Access' }
        if ($Apply -and $PSCmdlet.ShouldProcess($groupName, 'create security group')) {
            $group = Invoke-T0GraphWrite -Method POST -Uri 'groups' -Body @{
                displayName = $groupName; mailEnabled = $false; mailNickname = 'T0-BreakGlass'; securityEnabled = $true
                description = 'Target 0 emergency access accounts. Excluded from Conditional Access. Do not add other members.'
            }
            $result.status = 'applied'
        }
        $changes.Add($result); [pscustomobject]$result
    }

    foreach ($upn in $names) {
        $existing = (Invoke-T0Graph -Uri "users?`$filter=userPrincipalName eq '$upn'&`$select=id" -All | Select-Object -First 1)
        $result = [ordered]@{ account = $upn; action = 'create Global Administrator'; status = 'dry-run'; detail = ''; password = '' }
        if ($existing) {
            $result.status = 'exists'; $result.detail = 'left unchanged'
        }
        elseif ($Apply -and $PSCmdlet.ShouldProcess($upn, 'create break-glass Global Administrator')) {
            $password = Get-T0RandomPassword -Length 64
            $user = Invoke-T0GraphWrite -Method POST -Uri 'users' -Body @{
                accountEnabled = $true; displayName = "Emergency access $($upn.Split('@')[0])"; mailNickname = $upn.Split('@')[0]
                userPrincipalName = $upn; passwordProfile = @{ forceChangePasswordNextSignIn = $false; password = $password }
            }
            Invoke-T0GraphWrite -Method POST -Uri "groups/$($group['id'])/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user['id'])" } | Out-Null
            Invoke-T0GraphWrite -Method POST -Uri 'roleManagement/directory/roleAssignments' -Body @{
                principalId = $user['id']; roleDefinitionId = $script:T0GlobalAdminTemplate; directoryScopeId = '/'
            } | Out-Null
            $result.status = 'applied'; $result.password = $password
            $result.detail = 'store the password offline now; it is not saved anywhere'
        }
        # Log a copy without the password. (Select-Object -ExcludeProperty does not filter dictionary keys.)
        $logged = [ordered]@{}
        foreach ($key in $result.Keys) { if ($key -ne 'password') { $logged[$key] = $result[$key] } }
        $changes.Add($logged)
        [pscustomobject]$result
    }

    $dir = Get-T0RunDirectory -Config $Config -RunDate $RunDate
    $null = Save-T0ChangeLog -RunDirectory $dir -Name 'm365_breakglass' -Change $changes.ToArray() -Rollback @() -Property account -DryRun:(-not $Apply)
    Write-Information @'
Next steps for each break-glass account:
  1. Store the password offline (printed, in a safe). Two people should know where.
  2. Sign in once and register two FIDO2 security keys; keep them with the password.
  3. Check break_glass.m365 in targetzero.yaml lists both accounts.
  4. New-T0M365AdminCaPolicy excludes the T0-BreakGlass group from its policies.
  5. Make sure someone is told when these accounts sign in (Target 0, Zero 3).
'@ -InformationAction Continue
}
