# SPDX-License-Identifier: Apache-2.0
function Invoke-T0M365AdminInventory {
    <#
    .SYNOPSIS
        Lists every Microsoft 365 / Entra ID admin with role, permanence and MFA (Zero 1 and Zero 2).
    .DESCRIPTION
        Read-only. Writes, in output/<date>/:
          1_m365_admins.csv            one row per admin and role
          1_m365_admins.summary.json   Zero 1: permanent privileged admins
          2_m365_mfa.summary.json      Zero 2: admins without MFA that counts, or not enforced

        What it reads:
        - Directory role assignments. With Entra ID P2 (PIM), active and eligible schedules,
          so time-bound and eligible assignments are not counted as permanent.
        - Members of role-assignable groups that hold a role.
        - Apps holding high-risk Microsoft Graph application permissions (hidden admins).
        - Registered authentication methods per admin.
        - What enforces MFA: Security Defaults, Conditional Access policies (P1) and per-user MFA.

        Run Connect-T0M365 first.
    .EXAMPLE
        $config = Import-T0Config
        Connect-T0M365 -Config $config
        Invoke-T0M365AdminInventory -Config $config
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [datetime]$RunDate = (Get-Date)
    )
    $notes = [System.Collections.Generic.List[string]]::new()
    $complete = $true
    $privileged = @(Get-T0PrivilegedRole -Config $Config -Key 'm365')
    $riskyPermissions = @(Get-T0PrivilegedRole -Config $Config -Key 'm365_app_permissions')
    $breakGlass = @($Config.BreakGlass['m365'])
    $tenant = (Invoke-T0Graph -Uri 'organization?$select=id,verifiedDomains')['value'][0]
    $system = @($tenant['verifiedDomains'] | Where-Object { $_['isInitial'] })[0]['name']

    # --- Licences ------------------------------------------------------------------------------
    $plans = @(Invoke-T0Graph -Uri 'subscribedSkus' -All | Where-Object { $_['capabilityStatus'] -eq 'Enabled' } |
            ForEach-Object { $_['servicePlans'] } | ForEach-Object { $_['servicePlanName'] })
    $hasP2 = $plans -contains 'AAD_PREMIUM_P2'
    $hasP1 = $hasP2 -or ($plans -contains 'AAD_PREMIUM')
    $notes.Add("Entra ID licence: $(if ($hasP2) { 'P2' } elseif ($hasP1) { 'P1' } else { 'Free' })")
    if (-not $hasP2) { $notes.Add('No PIM (Entra ID P2): every active role assignment is permanent; keep the list as short as possible') }

    # --- Roles and assignments -----------------------------------------------------------------
    $roles = @{}
    foreach ($r in (Invoke-T0Graph -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,templateId' -All)) {
        $roles[$r['id']] = $r
    }
    $assignments = [System.Collections.Generic.List[object]]::new()
    if ($hasP2) {
        foreach ($a in (Invoke-T0Graph -Uri 'roleManagement/directory/roleAssignmentSchedules?$expand=principal' -All)) {
            $expiration = $a['scheduleInfo']['expiration']
            $timeBound = $a['assignmentType'] -eq 'Activated' -or ($expiration -and $expiration['type'] -ne 'noExpiration')
            $assignments.Add(@{ Raw = $a; State = 'active'; Permanent = -not $timeBound; End = if ($expiration) { $expiration['endDateTime'] } else { $null } })
        }
        foreach ($a in (Invoke-T0Graph -Uri 'roleManagement/directory/roleEligibilitySchedules?$expand=principal' -All)) {
            $expiration = $a['scheduleInfo']['expiration']
            $assignments.Add(@{ Raw = $a; State = 'eligible'; Permanent = $false; End = if ($expiration) { $expiration['endDateTime'] } else { $null } })
        }
    }
    else {
        foreach ($a in (Invoke-T0Graph -Uri 'roleManagement/directory/roleAssignments?$expand=principal' -All)) {
            $assignments.Add(@{ Raw = $a; State = 'active'; Permanent = $true; End = $null })
        }
    }

    # Expand to one entry per account and role. Group-held roles become one entry per member.
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $assignments) {
        $principal = $a.Raw['principal']
        $role = $roles[$a.Raw['roleDefinitionId']]
        $roleName = if ($role) { $role['displayName'] } else { $a.Raw['roleDefinitionId'] }
        $template = if ($role) { $role['templateId'] } else { $a.Raw['roleDefinitionId'] }
        $scopeNote = if ($a.Raw['directoryScopeId'] -and $a.Raw['directoryScopeId'] -ne '/') { "scoped to $($a.Raw['directoryScopeId'])" } else { '' }
        $base = @{ Role = $roleName; Template = $template; State = $a.State; Permanent = $a.Permanent; End = $a.End; Note = $scopeNote }
        switch ($principal['@odata.type']) {
            '#microsoft.graph.user' {
                $entries.Add($base + @{ Kind = 'user'; Id = $principal['id']; Via = '' })
            }
            '#microsoft.graph.group' {
                $members = Invoke-T0Graph -Uri "groups/$($principal['id'])/transitiveMembers/microsoft.graph.user?`$select=id" -All
                foreach ($m in $members) {
                    $entries.Add($base + @{ Kind = 'user'; Id = $m['id']; Via = "via group $($principal['displayName'])" })
                }
            }
            '#microsoft.graph.servicePrincipal' {
                $entries.Add($base + @{ Kind = 'service'; Id = $principal['id']; Name = $principal['displayName']; Via = '' })
            }
            default {
                $notes.Add("Role $roleName held by unsupported principal type $($principal['@odata.type'])")
            }
        }
    }

    # --- Users: details, methods, enforcement --------------------------------------------------
    $securityDefaults = (Invoke-T0Graph -Uri 'policies/identitySecurityDefaultsEnforcementPolicy')['isEnabled']
    if ($securityDefaults) { $notes.Add('Security Defaults on: MFA required for admin roles') }
    $policies = @()
    $strengthClass = $script:T0StrengthClass.Clone()
    if ($hasP1) {
        $policies = @(Invoke-T0Graph -Uri 'identity/conditionalAccess/policies' -All)
        $customIds = @($policies | ForEach-Object { $_['grantControls'] } | Where-Object { $_ -and $_['authenticationStrength'] } |
                ForEach-Object { $_['authenticationStrength']['id'] } | Where-Object { -not $strengthClass.ContainsKey($_) } | Select-Object -Unique)
        foreach ($id in $customIds) {
            $combos = @((Invoke-T0Graph -Uri "identity/conditionalAccess/authenticationStrength/policies/$id")['allowedCombinations'])
            $weak = @($combos | Where-Object { $_ -match 'sms|voice' }).Count -gt 0
            $strong = @($combos | Where-Object { $_ -notmatch '^(fido2|windowsHelloForBusiness|x509CertificateMultiFactor)$' }).Count -eq 0
            $strengthClass[$id] = if ($weak) { 'mfa' } elseif ($strong) { 'phishing-resistant' } else { 'mfa' }
        }
    }
    $usesGroups = @($policies | Where-Object { $_['conditions']['users']['includeGroups'] -or $_['conditions']['users']['excludeGroups'] }).Count -gt 0

    $userIds = @($entries | Where-Object { $_.Kind -eq 'user' } | ForEach-Object { $_.Id } | Select-Object -Unique)
    $userInfo = @{}
    foreach ($id in $userIds) {
        $select = 'id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,assignedLicenses'
        if ($hasP1) { $select += ',signInActivity' }
        $user = Invoke-T0Graph -Uri "users/$id`?`$select=$select"
        $upn = ([string]$user['userPrincipalName']).ToLowerInvariant()

        # Registered methods
        $unmapped = @()
        try {
            if ($hasP1) {
                $registered = @((Invoke-T0Graph -Uri "reports/authenticationMethods/userRegistrationDetails/$id")['methodsRegistered'])
                $mapped = Get-T0MethodClass -Method $registered -Kind Registered
            }
            else {
                $types = @(Invoke-T0Graph -Uri "users/$id/authentication/methods" -All | ForEach-Object { $_['@odata.type'] })
                $mapped = Get-T0MethodClass -Method $types -Kind Type
            }
            $classes = $mapped.Classes
            $unmapped = $mapped.Unmapped
            $methodsKnown = $true
        }
        catch {
            $classes = @()
            $methodsKnown = $false
            $notes.Add("Could not read methods for $upn`: $($_.Exception.Message)")
        }

        # Enforcement
        $roleTemplates = @($entries | Where-Object { $_.Kind -eq 'user' -and $_.Id -eq $id } | ForEach-Object { $_.Template })
        $groupIds = @(if ($usesGroups) { Invoke-T0Graph -Uri "users/$id/transitiveMemberOf?`$select=id" -All | ForEach-Object { $_['id'] } })
        $full = @()
        $partial = @()
        foreach ($p in $policies) {
            $result = Test-T0CaPolicyApply -Policy $p -UserId $id -GroupId $groupIds -RoleTemplateId $roleTemplates -StrengthClass $strengthClass
            if ($result) { if ($result.Partial) { $partial += $result } else { $full += $result } }
        }
        Write-Verbose "$upn`: roles $($roleTemplates -join ','); $(@($full).Count) enforcing and $(@($partial).Count) partial policies of $($policies.Count)"
        $perUser = ''
        try { $perUser = (Invoke-T0Graph -Uri "users/$id/authentication/requirements" -ApiVersion beta)['perUserMfaState'] } catch { Write-Verbose "per-user MFA state unavailable for $upn" }

        $strength = ''
        $enforcedBy = @()
        if ($full | Where-Object { $_.Strength -eq 'phishing-resistant' }) { $strength = 'phishing-resistant' }
        elseif ($full) { $strength = 'mfa' }
        $enforcedBy += @($full | ForEach-Object { $_.Reason })
        if ($securityDefaults) { $enforcedBy += 'Security Defaults'; if (-not $strength) { $strength = 'mfa' } }
        if ($perUser -in 'enforced', 'enabled') { $enforcedBy += "per-user MFA ($perUser)"; if (-not $strength) { $strength = 'mfa' } }
        $enforced = if ($strength) { 'Y' } elseif ($partial) { 'unknown' } else { 'N' }

        $mfaClass = if ($methodsKnown) { Get-T0MfaClass -Class $classes -EnforcedStrength $strength } else { 'unknown' }
        $detail = @()
        if ($enforcedBy) { $detail += 'enforced by: ' + ($enforcedBy -join ', ') }
        if ($partial) { $detail += 'partial: ' + (@($partial | ForEach-Object { $_.Reason }) -join ', ') }
        if ($unmapped) { $detail += 'unmapped methods: ' + ($unmapped -join ', ') }
        if ($user['onPremisesSyncEnabled']) { $detail += 'synced from on-premises AD (admins should be cloud-only)' }
        if ($user['accountEnabled'] -eq $false) { $detail += 'account disabled' }
        $licensed = @($user['assignedLicenses']).Count -gt 0
        if ($licensed) { $detail += 'licensed: likely also used for mail' }
        $lastSignIn = if ($user.ContainsKey('signInActivity') -and $user['signInActivity']) { $user['signInActivity']['lastSignInDateTime'] } else { '' }

        $userInfo[$id] = @{
            Upn = $upn; MfaClass = $mfaClass; Enforced = $enforced; Separate = if ($licensed) { 'N' } else { 'Y' }
            BreakGlass = if ($breakGlass -contains $upn) { 'Y' } else { 'N' }; LastLogon = [string]$lastSignIn; Detail = $detail
        }
    }

    # --- Records -------------------------------------------------------------------------------
    $records = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $entries) {
        if ($e.Kind -eq 'user') {
            $u = $userInfo[$e.Id]
            $account = $u.Upn
            $note = @($e.Via, $e.Note, "$($e.State)") + $u.Detail | Where-Object { $_ }
            $record = @{
                account_type = 'user'; mfa_class = $u.MfaClass; mfa_enforced = $u.Enforced
                separate_admin_account = $u.Separate; break_glass = $u.BreakGlass; last_logon = $u.LastLogon
            }
        }
        else {
            $account = "$($e.Name) (app)"
            $note = @($e.Note, 'application: MFA does not apply; Zero 1 only') | Where-Object { $_ }
            $record = @{ account_type = 'service'; mfa_class = 'none'; mfa_enforced = 'N'; separate_admin_account = ''; break_glass = 'N'; last_logon = '' }
        }
        $stateSuffix = if ($e.State -eq 'eligible') { 'eligible' } else { '' }
        $id = ConvertTo-T0Id -Source m365 -Part $system, $account, $e.Role, $stateSuffix
        if (-not $seen.Add($id)) { continue }
        $records.Add($record + @{
                id         = $id
                source     = 'm365'
                system     = $system
                account    = $account
                role       = $e.Role
                privileged = if ($privileged -contains $e.Role) { 'Y' } else { 'N' }
                permanent  = if ($e.Permanent) { 'Y' } else { 'N' }
                end_date   = if ($e.End) { ([datetime]$e.End).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { '' }
                notes      = $note -join '; '
            })
    }

    # Apps with high-risk Graph application permissions.
    try {
        $graph = Invoke-T0Graph -Uri "servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"
        $appRoles = @{}
        foreach ($r in $graph['appRoles']) { $appRoles[$r['id']] = $r['value'] }
        foreach ($grant in (Invoke-T0Graph -Uri "servicePrincipals/$($graph['id'])/appRoleAssignedTo" -All)) {
            $permission = $appRoles[$grant['appRoleId']]
            if ($riskyPermissions -notcontains $permission) { continue }
            $account = "$($grant['principalDisplayName']) (app)"
            $records.Add(@{
                    id = ConvertTo-T0Id -Source m365 -Part $system, $account, "graph-$permission"
                    source = 'm365'; system = $system; account = $account; role = "Graph application permission $permission"
                    account_type = 'service'; privileged = 'Y'; permanent = 'Y'; end_date = ''; mfa_class = 'none'; mfa_enforced = 'N'
                    separate_admin_account = ''; break_glass = 'N'; last_logon = ''
                    notes = 'hidden admin: application permission, no user sign-in needed'
                })
        }
    }
    catch {
        $complete = $false
        $notes.Add("Could not read application permissions: $($_.Exception.Message)")
    }

    $dir = Get-T0RunDirectory -Config $Config -RunDate $RunDate
    Export-T0AdminSummary -RunDirectory $dir -Source m365 -Records $records.ToArray() -Tool 'Invoke-T0M365AdminInventory' `
        -RunDate $RunDate -Complete $complete -Notes $notes.ToArray()
}
