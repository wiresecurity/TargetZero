# SPDX-License-Identifier: Apache-2.0
function Connect-T0M365 {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph with the read-only permissions the inventory needs.
    .DESCRIPTION
        Interactive by default: sign in with an account that holds Global Reader.
        -ReadWrite adds the permissions for the change commands. It always signs in interactively,
        so changes are made by a person, never by the unattended app.
        For unattended runs set m365.client_id and m365.certificate_thumbprint in targetzero.yaml
        (app registration with certificate and the same permissions as application permissions).
    .EXAMPLE
        $config = Import-T0Config
        Connect-T0M365 -Config $config
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        # Also request the permissions the change commands need. Interactive sign-in only.
        [switch]$ReadWrite
    )
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Graph PowerShell is not installed: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    $scopes = @(
        'Directory.Read.All'
        'RoleManagement.Read.Directory'
        'UserAuthenticationMethod.Read.All'
        'AuditLog.Read.All'
        'Policy.Read.All'
        'Application.Read.All'
        'Domain.Read.All'
    )
    if ($ReadWrite) {
        $scopes += @(
            'RoleManagement.ReadWrite.Directory'
            'AppRoleAssignment.ReadWrite.All'
            'Policy.ReadWrite.ConditionalAccess'
            'User.ReadWrite.All'
            'Group.ReadWrite.All'
        )
    }
    $settings = $Config.Data['m365']
    $tenant = if ($settings) { $settings['tenant_id'] } else { '' }
    $clientId = if ($settings) { $settings['client_id'] } else { '' }
    $thumbprint = if ($settings) { $settings['certificate_thumbprint'] } else { '' }

    $parameters = @{ NoWelcome = $true }
    if ($tenant) { $parameters['TenantId'] = $tenant }
    if ($clientId -and $thumbprint -and -not $ReadWrite) {
        $parameters['ClientId'] = $clientId
        $parameters['CertificateThumbprint'] = $thumbprint
    }
    else {
        $parameters['Scopes'] = $scopes
    }
    Connect-MgGraph @parameters
    $context = Get-MgContext
    Write-Verbose "Connected to tenant $($context.TenantId) as $($context.Account ?? $context.ClientId)"
}
