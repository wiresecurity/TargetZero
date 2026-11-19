# SPDX-License-Identifier: Apache-2.0
function Test-T0Json {
    <#
    .SYNOPSIS
        Validates a JSON string against a TargetZero schema and returns the problems found.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$Schema
    )
    $schemaErrors = @()
    $null = Test-Json -Json $Json -SchemaFile (Get-T0SchemaPath -Name $Schema) `
        -ErrorAction SilentlyContinue -ErrorVariable schemaErrors
    return @($schemaErrors | ForEach-Object { $_.Exception.Message })
}
