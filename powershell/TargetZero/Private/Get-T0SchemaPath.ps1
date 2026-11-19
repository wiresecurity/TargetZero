# SPDX-License-Identifier: Apache-2.0
function Get-T0SchemaPath {
    <#
    .SYNOPSIS
        Returns the path of a TargetZero JSON schema.
    .DESCRIPTION
        A published module carries the schemas in its own 'schemas' folder (copied by build.ps1).
        In a source checkout they are read from the repository's 'schema' folder.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('summary', 'admins', 'inventory', 'findings', 'exceptions', 'alert_tests', 'config')]
        [string]$Name
    )
    $candidates = @(
        (Join-Path $script:ModuleRoot 'schemas'),
        (Join-Path $script:ModuleRoot '..' '..' 'schema')
    )
    foreach ($folder in $candidates) {
        $file = Join-Path $folder "$Name.schema.json"
        if (Test-Path -LiteralPath $file) {
            return (Resolve-Path -LiteralPath $file).Path
        }
    }
    throw "TargetZero schema '$Name' not found. Run build.ps1 or use a complete source checkout."
}
