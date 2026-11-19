# SPDX-License-Identifier: Apache-2.0
# MFA classification for Microsoft 365. Pure functions, covered by Pester tests.

# Authentication method types (/users/{id}/authentication/methods).
$script:T0MethodTypeClass = @{
    '#microsoft.graph.fido2AuthenticationMethod'                  = 'phishing-resistant'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = 'phishing-resistant'
    '#microsoft.graph.platformCredentialAuthenticationMethod'     = 'phishing-resistant'
    '#microsoft.graph.x509CertificateAuthenticationMethod'        = 'phishing-resistant'
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' = 'mfa'
    '#microsoft.graph.softwareOathAuthenticationMethod'           = 'mfa'
    '#microsoft.graph.hardwareOathAuthenticationMethod'           = 'mfa'
    '#microsoft.graph.phoneAuthenticationMethod'                  = 'does-not-count'
    '#microsoft.graph.emailAuthenticationMethod'                  = 'ignore'
    '#microsoft.graph.passwordAuthenticationMethod'               = 'ignore'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'    = 'ignore'
}

# methodsRegistered values (/reports/authenticationMethods/userRegistrationDetails).
$script:T0RegisteredClass = @{
    'fido2'                          = 'phishing-resistant'
    'passKeyDeviceBound'             = 'phishing-resistant'
    'passKeyDeviceBoundAuthenticator' = 'phishing-resistant'
    'passKeyDeviceBoundWindowsHello' = 'phishing-resistant'
    'windowsHelloForBusiness'        = 'phishing-resistant'
    'macOsSecureEnclaveKey'          = 'phishing-resistant'
    'x509Certificate'                = 'phishing-resistant'
    'microsoftAuthenticatorPush'     = 'mfa'
    'microsoftAuthenticatorPasswordless' = 'mfa'
    'softwareOneTimePasscode'        = 'mfa'
    'hardwareOneTimePasscode'        = 'mfa'
    'mobilePhone'                    = 'does-not-count'
    'alternateMobilePhone'           = 'does-not-count'
    'officePhone'                    = 'does-not-count'
    'sms'                            = 'does-not-count'
    'voice'                          = 'does-not-count'
    'email'                          = 'ignore'
    'securityQuestion'               = 'ignore'
    'temporaryAccessPass'            = 'ignore'
    'appPassword'                    = 'ignore'
}

$script:T0Rank = @{ 'none' = 0; 'does-not-count' = 1; 'unknown' = 2; 'mfa' = 3; 'phishing-resistant' = 4 }

# Built-in authentication strengths.
$script:T0StrengthClass = @{
    '00000000-0000-0000-0000-000000000002' = 'mfa'
    '00000000-0000-0000-0000-000000000003' = 'mfa'
    '00000000-0000-0000-0000-000000000004' = 'phishing-resistant'
}

function Get-T0MethodClass {
    <#
    .SYNOPSIS
        Maps registered methods to classes. Returns @{ Classes = [string[]]; Unmapped = [string[]] }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Method,
        [ValidateSet('Type', 'Registered')][string]$Kind = 'Type'
    )
    $map = if ($Kind -eq 'Type') { $script:T0MethodTypeClass } else { $script:T0RegisteredClass }
    $classes = [System.Collections.Generic.List[string]]::new()
    $unmapped = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $Method) {
        if ($map.ContainsKey($m)) {
            if ($map[$m] -ne 'ignore') { $classes.Add($map[$m]) }
        }
        else { $unmapped.Add($m) }
    }
    return @{ Classes = @($classes | Select-Object -Unique); Unmapped = @($unmapped) }
}

function Get-T0MfaClass {
    <#
    .SYNOPSIS
        The MFA class an admin really has, given registered method classes and the enforced strength.
    .DESCRIPTION
        With a phishing-resistant strength enforced, only phishing-resistant methods can be used.
        Otherwise the weakest registered sign-in method is what an attacker can use, so it counts.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Class,
        [AllowEmptyString()][string]$EnforcedStrength = ''
    )
    if (-not $Class) { return 'none' }
    if ($EnforcedStrength -eq 'phishing-resistant') {
        if ($Class -contains 'phishing-resistant') { return 'phishing-resistant' }
        return 'unknown'
    }
    return ($Class | Sort-Object { $script:T0Rank[$_] } | Select-Object -First 1)
}

function Test-T0CaPolicyApply {
    <#
    .SYNOPSIS
        Does a Conditional Access policy require MFA of this admin on every sign-in?
    .OUTPUTS
        $null when it does not apply; otherwise @{ Strength = 'mfa'|'phishing-resistant'|'mfa-weak'; Partial = [bool]; Reason = [string] }.
        Partial means conditions (locations, platforms, risk, client apps, OR-ed controls) leave gaps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Policy,
        [Parameter(Mandatory)][string]$UserId,
        [AllowEmptyCollection()][string[]]$GroupId = @(),
        [AllowEmptyCollection()][string[]]$RoleTemplateId = @(),
        [hashtable]$StrengthClass = $script:T0StrengthClass
    )
    if ($Policy['state'] -ne 'enabled') { return $null }
    $conditions = $Policy['conditions']
    $users = $conditions['users']
    $grant = $Policy['grantControls']
    if (-not $grant) { return $null }

    $member = {
        param($ids, $groups, $roles, $user, $userGroups, $userRoles)
        # Skip nulls: in PowerShell, $null -contains $null is true.
        (@($ids) -contains 'All') -or (@($ids) -contains $user) -or
        (@($groups | Where-Object { $_ -and @($userGroups) -contains $_ }).Count -gt 0) -or
        (@($roles | Where-Object { $_ -and @($userRoles) -contains $_ }).Count -gt 0)
    }
    $included = & $member $users['includeUsers'] $users['includeGroups'] $users['includeRoles'] $UserId $GroupId $RoleTemplateId
    $excluded = & $member $users['excludeUsers'] $users['excludeGroups'] $users['excludeRoles'] $UserId $GroupId $RoleTemplateId
    if (-not $included -or $excluded) { return $null }
    $apps = $conditions['applications']
    if (-not $apps -or @($apps['includeApplications']) -notcontains 'All') { return $null }

    $strength = $null
    $strengthPolicy = $grant['authenticationStrength']
    if ($strengthPolicy -and $strengthPolicy['id']) {
        $strength = $StrengthClass[$strengthPolicy['id']]
        if (-not $strength) { $strength = 'mfa' }
    }
    elseif (@($grant['builtInControls'] | Where-Object { $_ }) -contains 'mfa') {
        $strength = 'mfa'
    }
    if (-not $strength) { return $null }

    $gaps = [System.Collections.Generic.List[string]]::new()
    $controls = @($grant['builtInControls'] | Where-Object { $_ })
    if ($controls.Count -gt 1 -and $grant['operator'] -eq 'OR') { $gaps.Add('MFA is one of several OR-ed controls') }
    $clientApps = @($conditions['clientAppTypes'] | Where-Object { $_ })
    if ($clientApps.Count -and $clientApps -notcontains 'all' -and
        -not ($clientApps -contains 'browser' -and $clientApps -contains 'mobileAppsAndDesktopClients')) {
        $gaps.Add('not all client apps')
    }
    if ($conditions['locations']) { $gaps.Add('location condition') }
    if ($conditions['platforms']) { $gaps.Add('platform condition') }
    if (@($conditions['signInRiskLevels'] | Where-Object { $_ }).Count -or @($conditions['userRiskLevels'] | Where-Object { $_ }).Count) { $gaps.Add('risk condition') }
    if ($conditions['devices']) { $gaps.Add('device filter') }

    return @{ Strength = $strength; Partial = ($gaps.Count -gt 0); Reason = "$($Policy['displayName'])$(if ($gaps.Count) { ' (' + ($gaps -join ', ') + ')' })" }
}
