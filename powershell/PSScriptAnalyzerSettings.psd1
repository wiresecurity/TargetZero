# SPDX-License-Identifier: Apache-2.0
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @()
    Rules        = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('7.0') }
    }
}
