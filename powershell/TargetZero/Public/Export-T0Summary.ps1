# SPDX-License-Identifier: Apache-2.0
function Export-T0Summary {
    <#
    .SYNOPSIS
        Validates and writes a count summary: <zero>_<source>_<name>.summary.json.
    .DESCRIPTION
        The summary is what the scorecard reads. It is checked against schema/summary.schema.json
        before it is written; count always equals the number of items, and item ids must be unique
        and stable between runs (exceptions refer to them).
    .EXAMPLE
        $items = @(@{ id = 'm365:admin@contoso.com/global-administrator'; reason = 'Permanent Global Administrator' })
        Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items $items -Tool 'Get-T0M365Admin'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][ValidateRange(1, 7)][int]$Zero,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]*$')][string]$Source,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]*$')][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][string]$Tool,
        [datetime]$RunDate = (Get-Date),
        [bool]$Complete = $true,
        [string[]]$Notes = @(),
        [string]$RecordFile,
        [string]$ToolVersion = $script:ModuleVersion
    )

    $itemList = @($Items | ForEach-Object { [ordered]@{ id = [string]$_.id; reason = [string]$_.reason } })
    $summary = [ordered]@{
        schema_version = '1.0'
        zero           = $Zero
        source         = $Source
        name           = $Name
        tool           = $Tool
        tool_version   = $ToolVersion
        run_date       = $RunDate.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
        generated_at   = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'+00:00'", [cultureinfo]::InvariantCulture)
        count          = $itemList.Count
        complete       = $Complete
        notes          = @($Notes)
        items          = $itemList
    }
    if ($RecordFile) { $summary['record_file'] = $RecordFile }

    $json = ConvertTo-Json -InputObject $summary -Depth 5
    $problems = @(Test-T0Json -Json $json -Schema 'summary')
    # Ids are compared case-sensitively, as in the Python tools.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $duplicates = @($itemList | Where-Object { -not $seen.Add($_.id) } | ForEach-Object { $_.id } | Select-Object -Unique)
    if ($duplicates) { $problems += "duplicate item ids: $($duplicates -join ', ')" }
    if ($problems) {
        throw "Summary does not match the schema:`n  $($problems -join "`n  ")"
    }

    $path = Join-Path $RunDirectory "$($Zero)_$($Source)_$($Name).summary.json"
    Set-Content -LiteralPath $path -Value $json -Encoding utf8NoBOM
    return $path
}
