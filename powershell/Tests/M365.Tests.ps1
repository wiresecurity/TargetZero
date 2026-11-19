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
                        @{ roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'jane' } }
                        @{ roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'bg' } }
                        @{ roleDefinitionId = $ga; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Tier0 Admins' } }
                        @{ roleDefinitionId = $reader; directoryScopeId = '/'; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp1'; displayName = 'Sync App' } }
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
                        @{ principalDisplayName = 'Backup App'; appRoleId = 'r-dir' }
                        @{ principalDisplayName = 'Report App'; appRoleId = 'r-read' }
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

    It 'writes the three files' {
        $paths | ForEach-Object { Split-Path -Leaf $_ } | Should -Be @('1_m365_admins.csv', '1_m365_admins.summary.json', '2_m365_mfa.summary.json')
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
