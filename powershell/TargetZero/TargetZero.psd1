# SPDX-License-Identifier: Apache-2.0
@{
    RootModule           = 'TargetZero.psm1'
    ModuleVersion        = '0.3.4'
    GUID                 = '033cdb50-d916-42db-8a12-36fac88b3e86'
    Author               = 'Wire Security'
    CompanyName          = 'Wire Security'
    Copyright            = 'Copyright 2026 Wire Security. Licensed under the Apache License 2.0.'
    Description          = 'Tooling for the Target 0 campaign: count, fix and report seven security zeros on Microsoft 365 and Entra ID.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    RequiredModules      = @('powershell-yaml')
    FunctionsToExport    = @(
        'Import-T0Config'
        'Get-T0RunDirectory'
        'Export-T0Record'
        'Export-T0Summary'
        'Export-T0AdminSummary'
        'Connect-T0M365'
        'Invoke-T0M365AdminInventory'
        'Get-T0M365Domain'
        'Set-T0M365RoleAssignment'
        'New-T0M365BreakGlassAccount'
        'New-T0M365AdminCaPolicy'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'M365', 'EntraID', 'MFA', 'Admin', 'Inventory', 'TargetZero')
            LicenseUri   = 'https://github.com/wiresecurity/TargetZero/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/wiresecurity/TargetZero'
            ReleaseNotes = 'https://github.com/wiresecurity/TargetZero/blob/main/CHANGELOG.md'
        }
    }
}
