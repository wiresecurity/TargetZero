# SPDX-License-Identifier: Apache-2.0
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TargetZero' 'TargetZero.psd1') -Force
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
}

Describe 'ConvertTo-T0Id' {
    It 'matches the Python id rules' {
        InModuleScope TargetZero {
            ConvertTo-T0Id -Source m365 -Part 'Contoso', ' Jane@X.com ', 'Global  Administrator', '' |
                Should -Be 'm365:contoso/jane@x.com/global-administrator'
            ConvertTo-T0Id -Source manual -Part 'Main firewall;2', 'admin' | Should -Be 'manual:main-firewall-2/admin'
        }
    }
}

Describe 'MFA classification' {
    It 'maps method types and registered method names' {
        InModuleScope TargetZero {
            $r = Get-T0MethodClass -Kind Type -Method '#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.phoneAuthenticationMethod', '#microsoft.graph.passwordAuthenticationMethod', '#microsoft.graph.newThing'
            $r.Classes | Should -Be @('phishing-resistant', 'does-not-count')
            $r.Unmapped | Should -Be @('#microsoft.graph.newThing')
            (Get-T0MethodClass -Kind Registered -Method 'microsoftAuthenticatorPush', 'email').Classes | Should -Be @('mfa')
        }
    }

    It 'uses the weakest method unless a phishing-resistant strength is enforced' {
        InModuleScope TargetZero {
            Get-T0MfaClass -Class @() | Should -Be 'none'
            Get-T0MfaClass -Class 'phishing-resistant', 'does-not-count' | Should -Be 'does-not-count'
            Get-T0MfaClass -Class 'phishing-resistant', 'does-not-count' -EnforcedStrength 'phishing-resistant' | Should -Be 'phishing-resistant'
            Get-T0MfaClass -Class 'mfa' -EnforcedStrength 'phishing-resistant' | Should -Be 'unknown'
        }
    }
}

Describe 'Test-T0CaPolicyApply' {
    BeforeAll {
        $script:policy = @{
            displayName   = 'Admins phishing-resistant'
            state         = 'enabled'
            conditions    = @{
                users        = @{ includeRoles = @('role-ga'); excludeUsers = @('bg') }
                applications = @{ includeApplications = @('All') }
            }
            grantControls = @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
        }
    }

    It 'applies to role holders with the policy strength' {
        InModuleScope TargetZero -Parameters @{ Policy = $policy } {
            $r = Test-T0CaPolicyApply -Policy $Policy -UserId 'u1' -RoleTemplateId 'role-ga'
            $r.Strength | Should -Be 'phishing-resistant'
            $r.Partial | Should -BeFalse
        }
    }

    It 'respects exclusions, report-only state and app scope' {
        InModuleScope TargetZero -Parameters @{ Policy = $policy } {
            Test-T0CaPolicyApply -Policy $Policy -UserId 'bg' -RoleTemplateId 'role-ga' | Should -BeNullOrEmpty
            Test-T0CaPolicyApply -Policy $Policy -UserId 'u1' -RoleTemplateId 'other' | Should -BeNullOrEmpty
            # No group ids at all must not count as "member of the excluded groups".
            (Test-T0CaPolicyApply -Policy $Policy -UserId 'u1' -GroupId $null -RoleTemplateId 'role-ga').Strength | Should -Be 'phishing-resistant'
            $reportOnly = $Policy.Clone(); $reportOnly['state'] = 'enabledForReportingButNotEnforced'
            Test-T0CaPolicyApply -Policy $reportOnly -UserId 'u1' -RoleTemplateId 'role-ga' | Should -BeNullOrEmpty
        }
    }

    It 'marks location conditions and OR-ed controls as partial' {
        InModuleScope TargetZero {
            $p = @{
                displayName   = 'MFA except office'
                state         = 'enabled'
                conditions    = @{
                    users        = @{ includeUsers = @('All') }
                    applications = @{ includeApplications = @('All') }
                    locations    = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') }
                }
                grantControls = @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') }
            }
            $r = Test-T0CaPolicyApply -Policy $p -UserId 'u1'
            $r.Strength | Should -Be 'mfa'
            $r.Partial | Should -BeTrue
            $r.Reason | Should -Match 'location condition'
            $r.Reason | Should -Match 'OR-ed'
        }
    }
}

Describe 'Export-T0AdminSummary' {
    It 'counts the shared cases exactly like the Python implementation' {
        $cases = Get-Content -LiteralPath (Join-Path $RepoRoot 'tests' 'shared' 'admin-count-cases.json') -Raw | ConvertFrom-Json -AsHashtable
        $dir = Join-Path $TestDrive 'shared'
        $null = New-Item -ItemType Directory -Path $dir
        $records = @($cases['records'] | ForEach-Object { $_['id'] = 'x:' + [guid]::NewGuid(); $_ })
        Export-T0AdminSummary -RunDirectory $dir -Source m365 -Records $records -Tool test | Out-Null
        $zero1 = Get-Content (Join-Path $dir '1_m365_admins.summary.json') -Raw | ConvertFrom-Json
        $zero2 = Get-Content (Join-Path $dir '2_m365_mfa.summary.json') -Raw | ConvertFrom-Json
        @($zero1.items.id | Sort-Object -CaseSensitive) | Should -Be $cases['expected_zero1']
        @($zero2.items.id | Sort-Object -CaseSensitive) | Should -Be $cases['expected_zero2']
    }
}

Describe 'Invoke-T0M365AdminInventory' {
    BeforeAll {
        $configPath = Join-Path $TestDrive 'targetzero.yaml'
        Set-Content -LiteralPath $configPath -Value @'
organisation: Contoso
break_glass:
  m365: [BG@contoso.onmicrosoft.com]
'@
        $script:config = Import-T0Config -Path $configPath

        Mock -ModuleName TargetZero Invoke-T0Graph {
            $ga = '62e90394-69f5-4237-9190-012177145e10'
            $reader = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
            $users = @{
                jane = @{ id = 'jane'; userPrincipalName = 'Jane@contoso.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'e5' }); signInActivity = @{ lastSignInDateTime = '2026-11-18T07:00:00Z' } }
                bob  = @{ id = 'bob'; userPrincipalName = 'bob@contoso.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @(); signInActivity = $null }
                bg   = @{ id = 'bg'; userPrincipalName = 'bg@contoso.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @(); signInActivity = $null }
            }
            $methods = @{ jane = @('fido2', 'mobilePhone'); bob = @('microsoftAuthenticatorPush'); bg = @() }
            switch -Wildcard ($Uri) {
                'organization*' { return @{ value = @(@{ id = 't1'; verifiedDomains = @(@{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) }) } }
                'subscribedSkus' { return @(@{ capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM' }) }) }
                'roleManagement/directory/roleDefinitions*' {
                    return @(@{ id = $ga; displayName = 'Global Administrator'; templateId = $ga }, @{ id = $reader; displayName = 'Global Reader'; templateId = $reader })
                }
                'roleManagement/directory/roleAssignments*' {
                    return @(
                        @{ id = 'a1'; roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'jane' } }
                        @{ id = 'a2'; roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'bg' } }
                        @{ id = 'a3'; roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Tier0 Admins' } }
                        @{ id = 'a4'; roleDefinitionId = $reader; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp1'; displayName = 'Sync App' } }
                    )
                }
                'groups/g1/transitiveMembers*' { return @(@{ id = 'bob' }) }
                'policies/identitySecurityDefaultsEnforcementPolicy' { return @{ isEnabled = $false } }
                'identity/conditionalAccess/policies' {
                    return @(@{
                            displayName = 'Admins phishing-resistant'; state = 'enabled'
                            conditions = @{ users = @{ includeRoles = @($ga); excludeUsers = @('bg') }; applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                            grantControls = @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
                        })
                }
                'reports/authenticationMethods/userRegistrationDetails/*' { return @{ methodsRegistered = $methods[$Uri.Split('/')[-1]] } }
                'users/*/authentication/requirements' { return @{ perUserMfaState = 'disabled' } }
                'users/*' { return $users[$Uri.Split('/')[1].Split('?')[0]] }
                'servicePrincipals(appId=*' { return @{ id = 'graph'; appRoles = @(@{ id = 'r-dir'; value = 'Directory.ReadWrite.All' }, @{ id = 'r-read'; value = 'User.Read.All' }) } }
                'servicePrincipals/graph/appRoleAssignedTo' {
                    return @(
                        @{ id = 'ara1'; principalId = 'sp-backup'; resourceId = 'graph'; principalDisplayName = 'Backup App'; appRoleId = 'r-dir' }
                        @{ id = 'ara2'; principalId = 'sp-report'; resourceId = 'graph'; principalDisplayName = 'Report App'; appRoleId = 'r-read' }
                    )
                }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
        $script:paths = Invoke-T0M365AdminInventory -Config $config -RunDate ([datetime]'2026-11-19')
        $script:dir = Split-Path -Parent $paths[0]
        $script:rows = Import-Csv (Join-Path $dir '1_m365_admins.csv')
        $script:zero1 = Get-Content (Join-Path $dir '1_m365_admins.summary.json') -Raw | ConvertFrom-Json
        $script:zero2 = Get-Content (Join-Path $dir '2_m365_mfa.summary.json') -Raw | ConvertFrom-Json
    }

    It 'writes the role plan and the three admin files' {
        $paths | ForEach-Object { Split-Path -Leaf $_ } | Should -Be @('1_m365_role-plan.csv', '1_m365_admins.csv', '1_m365_admins.summary.json', '2_m365_mfa.summary.json')
    }

    It 'writes one plan row per stored assignment, groups not expanded' {
        $plan = Import-Csv (Join-Path $dir '1_m365_role-plan.csv')
        $plan.account | Should -Be @('Jane@contoso.onmicrosoft.com'.ToLower(), 'bg@contoso.onmicrosoft.com', 'Tier0 Admins (group)', 'Sync App (app)', 'Backup App (app)')
        ($plan | Where-Object account -EQ 'bg@contoso.onmicrosoft.com').break_glass | Should -Be 'Y'
        ($plan | Where-Object kind -EQ 'app-permission').app_role_id | Should -Be 'r-dir'
        $plan.action | ForEach-Object { $_ | Should -BeNullOrEmpty }
        $plan[0].plan_id | Should -Be 'P0001'
    }

    It 'expands group members and lists apps with risky permissions only' {
        ($rows | Where-Object account -EQ 'bob@contoso.onmicrosoft.com').notes | Should -Match 'via group Tier0 Admins'
        $rows.account | Should -Contain 'Backup App (app)'
        $rows.account | Should -Not -Contain 'Report App (app)'
    }

    It 'counts Zero 1: permanent privileged admins, break-glass excluded' {
        @($zero1.items.id | Sort-Object) | Should -Be @(
            'm365:contoso.onmicrosoft.com/backup-app-(app)'
            'm365:contoso.onmicrosoft.com/bob@contoso.onmicrosoft.com'
            'm365:contoso.onmicrosoft.com/jane@contoso.onmicrosoft.com'
        )
        $zero1.notes | Should -Contain 'Entra ID licence: P1'
    }

    It 'counts Zero 2: break-glass without MFA, and an admin who cannot meet the enforced strength' {
        @($zero2.items.id | Sort-Object) | Should -Be @(
            'm365:contoso.onmicrosoft.com/bg@contoso.onmicrosoft.com'
            'm365:contoso.onmicrosoft.com/bob@contoso.onmicrosoft.com'
        )
        $jane = $rows | Where-Object account -EQ 'jane@contoso.onmicrosoft.com'
        $jane.mfa_class | Should -Be 'phishing-resistant'
        $jane.mfa_enforced | Should -Be 'Y'
        $jane.separate_admin_account | Should -Be 'N'
    }
}

Describe 'Graph errors' {
    BeforeAll {
        # CI does not install Microsoft.Graph.Authentication: give Pester a command to mock.
        if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-MgGraphRequest {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub, replaced by Mock')]
                [CmdletBinding()]
                param($Method, $Uri, $OutputType, $Body, $ContentType)
            }
        }
        $script:notFound = 'GET https://graph.microsoft.com/v1.0/users/x HTTP/2.0 404 Not Found Cache-Control: no-cache {"error":{"code":"Request_ResourceNotFound","message":"Resource ''x'' does not exist.","innerError":{}}}'
    }
    AfterAll {
        Remove-Item function:global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    }

    It 'stop reads and writes instead of continuing with an empty result' {
        # Invoke-MgGraphRequest reports errors as non-terminating, unless the caller passes -ErrorAction.
        Mock -ModuleName TargetZero Invoke-MgGraphRequest { Write-Error $notFound -ErrorAction $PesterBoundParameters['ErrorAction'] }
        InModuleScope TargetZero {
            { Invoke-T0Graph -Uri 'users/x' } | Should -Throw '*Request_ResourceNotFound*'
            { Invoke-T0Graph -Uri 'users' -All } | Should -Throw
            { Invoke-T0GraphWrite -Method DELETE -Uri 'users/x' } | Should -Throw
        }
    }

    It 'are shortened to code and message' {
        Mock -ModuleName TargetZero Invoke-MgGraphRequest { Write-Error $notFound -ErrorAction $PesterBoundParameters['ErrorAction'] }
        InModuleScope TargetZero {
            $message = try { Invoke-T0Graph -Uri 'users/x' } catch { Get-T0GraphError -ErrorRecord $_ }
            $message | Should -Be "Request_ResourceNotFound: Resource 'x' does not exist."
        }
    }

    It 'mark a failed role change as failed, without a rollback row' {
        $folder = Join-Path $TestDrive 'failed-change'
        $null = New-Item -ItemType Directory -Path $folder
        Set-Content -LiteralPath (Join-Path $folder 'targetzero.yaml') -Value 'organisation: Contoso'
        $config = Import-T0Config -Path (Join-Path $folder 'targetzero.yaml')
        $planPath = Join-Path $folder 'plan.csv'
        $fields = InModuleScope TargetZero { $script:T0RolePlanFields }
        $row = [ordered]@{}
        foreach ($f in $fields) { $row[$f] = '' }
        $row.plan_id = 'P1'; $row.kind = 'role'; $row.account = 'eve@contoso.onmicrosoft.com'; $row.principal_id = 'eve'
        $row.role = 'User Administrator'; $row.role_definition_id = 'y'; $row.state = 'active'; $row.assignment_id = 'a9'; $row.action = 'remove'
        [pscustomobject]$row | Export-Csv -LiteralPath $planPath

        Mock -ModuleName TargetZero Invoke-T0Graph {
            switch -Wildcard ($Uri) {
                'subscribedSkus' { return @() }
                'roleManagement/directory/roleAssignments?*' { return @(@{ id = 'a1' }, @{ id = 'a2' }) }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
        Mock -ModuleName TargetZero Invoke-MgGraphRequest { Write-Error ($notFound -replace 'GET', 'DELETE') -ErrorAction $PesterBoundParameters['ErrorAction'] }
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $planPath -Apply -Confirm:$false -RunDate ([datetime]'2026-11-20')
        $out.status | Should -Be 'failed'
        $out.detail | Should -Be "Request_ResourceNotFound: Resource 'x' does not exist."
        $rollback = Get-ChildItem (Join-Path $folder 'output' '2026-11-20') -Filter 'rollback_*'
        if ($rollback) { @(Import-Csv $rollback.FullName) | Should -HaveCount 0 }
    }
}

Describe 'Invoke-T0M365AdminInventory with a deleted role holder' {
    BeforeAll {
        $configPath = Join-Path $TestDrive 'deleted' 'targetzero.yaml'
        $null = New-Item -ItemType Directory -Path (Split-Path $configPath) -Force
        Set-Content -LiteralPath $configPath -Value 'organisation: Contoso'
        $script:config = Import-T0Config -Path $configPath
        $script:failWith = 'Request_ResourceNotFound'

        Mock -ModuleName TargetZero Invoke-T0Graph {
            $ga = '62e90394-69f5-4237-9190-012177145e10'
            switch -Wildcard ($Uri) {
                'organization*' { return @{ value = @(@{ id = 't1'; verifiedDomains = @(@{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) }) } }
                'subscribedSkus' { return @() }
                'roleManagement/directory/roleDefinitions*' { return @(@{ id = $ga; displayName = 'Global Administrator'; templateId = $ga }) }
                'roleManagement/directory/roleAssignments*' {
                    return @(
                        @{ id = 'a1'; roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'jane' } }
                        @{ id = 'a2'; roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'f4243ce9-dead' } }
                    )
                }
                'policies/identitySecurityDefaultsEnforcementPolicy' { return @{ isEnabled = $true } }
                'users/f4243ce9-dead?*' { throw "GET https://graph.microsoft.com/v1.0/$Uri HTTP/2.0 404 Not Found {`"error`":{`"code`":`"$script:failWith`",`"message`":`"Resource 'f4243ce9-dead' does not exist.`"}}" }
                'users/jane?*' { return @{ id = 'jane'; userPrincipalName = 'jane@contoso.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @() } }
                'users/jane/authentication/methods' { return @(@{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' }) }
                'users/*/authentication/requirements' { return @{ perUserMfaState = 'disabled' } }
                'servicePrincipals(appId=*' { return @{ id = 'graph'; appRoles = @() } }
                'servicePrincipals/graph/appRoleAssignedTo' { return @() }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
    }

    It 'still counts the assignment, with MFA unknown and a note' {
        $paths = Invoke-T0M365AdminInventory -Config $config -RunDate ([datetime]'2026-11-20')
        $dir = Split-Path -Parent $paths[0]
        $rows = Import-Csv (Join-Path $dir '1_m365_admins.csv')
        $ghost = $rows | Where-Object account -EQ 'f4243ce9-dead'
        $ghost.mfa_class | Should -Be 'unknown'
        $ghost.notes | Should -Match 'user object not found'
        $zero1 = Get-Content (Join-Path $dir '1_m365_admins.summary.json') -Raw | ConvertFrom-Json
        $zero1.items.id | Should -Contain 'm365:contoso.onmicrosoft.com/f4243ce9-dead'
        $zero1.complete | Should -BeTrue
        ($zero1.notes -join ' | ') | Should -Match 'stale role assignment'
        $zero2 = Get-Content (Join-Path $dir '2_m365_mfa.summary.json') -Raw | ConvertFrom-Json
        $zero2.items.id | Should -Contain 'm365:contoso.onmicrosoft.com/f4243ce9-dead'
        $plan = Import-Csv (Join-Path $dir '1_m365_role-plan.csv')
        ($plan | Where-Object account -EQ 'f4243ce9-dead').assignment_id | Should -Be 'a2'
    }

    It 'stops on other errors instead of writing wrong counts' {
        $script:failWith = 'Authorization_RequestDenied'
        { Invoke-T0M365AdminInventory -Config $config -RunDate ([datetime]'2026-11-21') } | Should -Throw '*Authorization_RequestDenied*'
        Join-Path (Split-Path $configPath) 'output' '2026-11-21' '1_m365_admins.summary.json' | Should -Not -Exist
    }
}
