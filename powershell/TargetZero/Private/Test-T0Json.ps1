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
    $valid = Test-Json -Json $Json -SchemaFile (Get-T0SchemaPath -Name $Schema) `
        -ErrorAction SilentlyContinue -ErrorVariable schemaErrors
    $messages = @($schemaErrors | ForEach-Object { $_.Exception.Message })
    # Some failures (e.g. a pattern mismatch) only show in the return value, not as an error record.
    if (-not $valid -and -not $messages) { $messages = @("does not match $Schema.schema.json") }
    return $messages
}
