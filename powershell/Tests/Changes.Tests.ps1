# SPDX-License-Identifier: Apache-2.0
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TargetZero' 'TargetZero.psd1') -Force
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'

    function Get-TestConfig {
        param([string]$Folder)
        $null = New-Item -ItemType Directory -Path $Folder -Force
        $path = Join-Path $Folder 'targetzero.yaml'
        Set-Content -LiteralPath $path -Value "organisation: Contoso`nbreak_glass:`n  m365: [bg@contoso.onmicrosoft.com]"
        Import-T0Config -Path $path
    }

    function Export-TestPlan {
        param([string]$Path, [object[]]$Rows)
        $fields = InModuleScope TargetZero { $script:T0RolePlanFields }
        $Rows | ForEach-Object {
            $row = [ordered]@{}
            foreach ($f in $fields) { $row[$f] = if ($_.Contains($f)) { $_[$f] } else { '' } }
            [pscustomobject]$row
        } | Export-Csv -LiteralPath $Path -NoTypeInformation
    }
}

Describe 'Get-T0RandomPassword' {
    It 'is long and random' {
        InModuleScope TargetZero {
            $a = Get-T0RandomPassword -Length 64
            $a.Length | Should -Be 64
            $a | Should -Not -Be (Get-T0RandomPassword -Length 64)
            $a | Should -Match '^[A-Za-z0-9!#%+\-.:=?@_~]+$'
        }
    }
}

Describe 'Set-T0M365RoleAssignment' {
    BeforeEach {
        $script:folder = Join-Path $TestDrive ([guid]::NewGuid())
        $script:config = Get-TestConfig -Folder $folder
        $script:planPath = Join-Path $folder 'plan.csv'
        $script:activeGa = 2
        Mock -ModuleName TargetZero Invoke-T0Graph {
            switch -Wildcard ($Uri) {
                'subscribedSkus' { return @(@{ capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM' }) }) }
                'roleManagement/directory/roleAssignments?*' { return @(1..$script:activeGa | ForEach-Object { @{ id = "a$_" } }) }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
        Mock -ModuleName TargetZero Invoke-T0GraphWrite { @{ id = 'new-id' } }
        Export-TestPlan -Path $planPath -Rows @(
            @{ plan_id = 'P1'; kind = 'role'; account = 'jane@contoso.onmicrosoft.com'; principal_id = 'jane'; role = 'Global Administrator'; role_definition_id = $GA; directory_scope_id = '/'; state = 'active'; assignment_id = 'a1'; action = 'remove' }
            @{ plan_id = 'P2'; kind = 'role'; account = 'BG@contoso.onmicrosoft.com'; principal_id = 'bg'; role = 'Global Administrator'; role_definition_id = $GA; state = 'active'; assignment_id = 'a2'; action = 'remove' }
            @{ plan_id = 'P3'; kind = 'app-permission'; account = 'Backup App (app)'; principal_id = 'sp-backup'; resource_id = 'graph'; app_role_id = 'r-dir'; state = 'active'; assignment_id = 'ara1'; action = 'remove' }
            @{ plan_id = 'P4'; kind = 'role'; account = 'bob@contoso.onmicrosoft.com'; principal_id = 'bob'; role = 'Exchange Administrator'; role_definition_id = 'x'; state = 'active'; action = 'make-eligible' }
            @{ plan_id = 'P5'; kind = 'role'; account = 'eve@contoso.onmicrosoft.com'; principal_id = 'eve'; role = 'User Administrator'; role_definition_id = 'y'; state = 'active'; action = '' }
        )
    }

    It 'changes nothing without -Apply' {
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $planPath -RunDate ([datetime]'2026-11-19')
        $out.status | Should -Be @('dry-run', 'refused', 'dry-run', 'refused')
        ($out | Where-Object plan_id -EQ 'P2').detail | Should -Match 'break-glass'
        ($out | Where-Object plan_id -EQ 'P4').detail | Should -Match 'P2'
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 0
        Get-ChildItem (Join-Path $folder 'output' '2026-11-19') -Filter 'dryrun_*' | Should -HaveCount 1
    }

    It 'applies, logs and writes a rollback plan' {
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $planPath -Apply -Confirm:$false -RunDate ([datetime]'2026-11-19')
        ($out | Where-Object status -EQ 'applied').plan_id | Should -Be @('P1', 'P3')
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 1 -ParameterFilter { $Method -eq 'DELETE' -and $Uri -eq 'roleManagement/directory/roleAssignments/a1' }
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 1 -ParameterFilter { $Method -eq 'DELETE' -and $Uri -eq 'servicePrincipals/sp-backup/appRoleAssignments/ara1' }
        $rollback = Import-Csv (Get-ChildItem (Join-Path $folder 'output' '2026-11-19') -Filter 'rollback_*').FullName
        $rollback.action | Should -Be @('restore-active', 'restore-app-permission')
    }

    It 'rolls back from the rollback plan' {
        Set-T0M365RoleAssignment -Config $config -PlanPath $planPath -Apply -Confirm:$false -RunDate ([datetime]'2026-11-19') | Out-Null
        $rollbackPath = (Get-ChildItem (Join-Path $folder 'output' '2026-11-19') -Filter 'rollback_*').FullName
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $rollbackPath -Apply -Confirm:$false -RunDate ([datetime]'2026-11-19')
        $out.status | Should -Be @('applied', 'applied')
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -ParameterFilter { $Method -eq 'POST' -and $Uri -eq 'roleManagement/directory/roleAssignments' -and $Body.principalId -eq 'jane' }
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -ParameterFilter { $Method -eq 'POST' -and $Uri -eq 'servicePrincipals/sp-backup/appRoleAssignments' -and $Body.appRoleId -eq 'r-dir' }
    }

    It 'reads a plan that Excel saved with semicolons' {
        $text = (Get-Content -LiteralPath $planPath -Raw) -replace '","', '";"'
        Set-Content -LiteralPath $planPath -Value $text -Encoding utf8BOM
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $planPath
        $out.status | Should -Be @('dry-run', 'refused', 'dry-run', 'refused')
    }

    It 'refuses to remove the last active Global Administrator' {
        $script:activeGa = 1
        $out = Set-T0M365RoleAssignment -Config $config -PlanPath $planPath -Apply -Confirm:$false
        ($out | Where-Object plan_id -EQ 'P1').status | Should -Be 'refused'
        ($out | Where-Object plan_id -EQ 'P1').detail | Should -Match 'no active Global Administrator'
    }
}

Describe 'New-T0M365AdminCaPolicy' {
    BeforeEach {
        $script:folder = Join-Path $TestDrive ([guid]::NewGuid())
        $script:config = Get-TestConfig -Folder $folder
        $script:p1 = $true
        Mock -ModuleName TargetZero Invoke-T0Graph {
            switch -Wildcard ($Uri) {
                'subscribedSkus' { return @(@{ capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanName = $(if ($script:p1) { 'AAD_PREMIUM' } else { 'EXCHANGE_S_STANDARD' }) }) }) }
                'policies/identitySecurityDefaultsEnforcementPolicy' { return @{ isEnabled = $false } }
                'groups?*' { return @(@{ id = 'bg-group' }) }
                'roleManagement/directory/roleDefinitions*' {
                    return @(
                        @{ displayName = 'Global Administrator'; templateId = $GA }
                        @{ displayName = 'Directory Synchronization Accounts'; templateId = 'sync' }
                        @{ displayName = 'Global Reader'; templateId = 'reader' }
                    )
                }
                'identity/conditionalAccess/policies*' { return @() }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
        Mock -ModuleName TargetZero Invoke-T0GraphWrite { @{ id = 'policy-id' } }
    }

    It 'creates report-only policies that exclude break-glass and the sync role' {
        $out = New-T0M365AdminCaPolicy -Config $config -Apply -Confirm:$false
        $out.status | Should -Be @('applied', 'applied')
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 2 -ParameterFilter {
            $Body.state -eq 'enabledForReportingButNotEnforced' -and $Body.conditions.users.excludeGroups -contains 'bg-group'
        }
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 1 -ParameterFilter {
            ($Body.conditions.users.includeRoles -join ',') -eq $GA
        }
    }

    It 'refuses to enforce while an admin has no phishing-resistant method' {
        $day = Join-Path $config.OutputDirectory '2026-11-19'
        $null = New-Item -ItemType Directory -Path $day -Force
        @([pscustomobject]@{ account = 'jane@contoso.onmicrosoft.com'; privileged = 'Y'; account_type = 'user'; break_glass = 'N'; mfa_class = 'mfa' }) |
            Export-Csv (Join-Path $day '1_m365_admins.csv') -NoTypeInformation
        { New-T0M365AdminCaPolicy -Config $config -Apply -Enable -Confirm:$false } | Should -Throw '*jane@contoso.onmicrosoft.com*'
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 0
    }

    It 'offers Security Defaults without Entra ID P1' {
        $script:p1 = $false
        (New-T0M365AdminCaPolicy -Config $config -Apply -Confirm:$false).status | Should -Be 'refused'
        (New-T0M365AdminCaPolicy -Config $config -Apply -UseSecurityDefaults -Confirm:$false).status | Should -Be 'applied'
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 1 -ParameterFilter { $Method -eq 'PATCH' -and $Body.isEnabled }
    }
}

Describe 'New-T0M365BreakGlassAccount' {
    BeforeEach {
        $script:folder = Join-Path $TestDrive ([guid]::NewGuid())
        $script:config = Get-TestConfig -Folder $folder
        Mock -ModuleName TargetZero Invoke-T0Graph {
            switch -Wildcard ($Uri) {
                'organization*' { return @{ value = @(@{ verifiedDomains = @(@{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) }) } }
                'groups?*' { return @() }
                'users?*' { return @() }
                default { throw "Unexpected Graph call: $Uri" }
            }
        }
        Mock -ModuleName TargetZero Invoke-T0GraphWrite { @{ id = 'new-id' } }
    }

    It 'only reports in a dry run' {
        $out = New-T0M365BreakGlassAccount -Config $config 3>$null
        $out.status | Should -Be @('dry-run', 'dry-run')
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 0
    }

    It 'creates group, user, membership and role, and never logs the password' {
        $out = New-T0M365BreakGlassAccount -Config $config -Apply -Confirm:$false
        $created = $out | Where-Object account -EQ 'bg@contoso.onmicrosoft.com'
        $created.password.Length | Should -Be 64
        Should -Invoke -ModuleName TargetZero Invoke-T0GraphWrite -Times 1 -ParameterFilter { $Uri -eq 'roleManagement/directory/roleAssignments' -and $Body.roleDefinitionId -eq $GA }
        $log = Get-ChildItem $config.OutputDirectory -Recurse -Filter 'changes_m365_breakglass_*' | Get-Content -Raw
        $log | Should -Not -Match ([regex]::Escape($created.password))
    }
}
