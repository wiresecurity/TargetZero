# SPDX-License-Identifier: Apache-2.0
function Import-T0Config {
    <#
    .SYNOPSIS
        Loads and validates targetzero.yaml.
    .DESCRIPTION
        Looks for the file in this order: -Path, $env:TARGETZERO_CONFIG, ./targetzero.yaml,
        ./config/targetzero.yaml. The file is checked against schema/config.schema.json, the same
        schema the Python tools use. Relative paths in the file are resolved against its folder.
    .EXAMPLE
        $config = Import-T0Config
        $config.BreakGlass['m365']
    #>
    [CmdletBinding()]
    [OutputType('TargetZero.Config')]
    param(
        [string]$Path
    )

    $candidates = if ($Path) { @($Path) }
    elseif ($env:TARGETZERO_CONFIG) { @($env:TARGETZERO_CONFIG) }
    else { @('targetzero.yaml', (Join-Path 'config' 'targetzero.yaml')) }
    $file = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $file) {
        throw "No TargetZero configuration found (tried: $($candidates -join ', ')). Run 'targetzero init', pass -Path, or set TARGETZERO_CONFIG."
    }
    $file = (Resolve-Path -LiteralPath $file).Path

    try {
        $yaml = ConvertFrom-Yaml -Yaml (Get-Content -LiteralPath $file -Raw)
    }
    catch {
        throw "$file is not valid YAML: $($_.Exception.Message)"
    }
    if ($yaml -isnot [System.Collections.IDictionary]) {
        throw "$file must contain a mapping at the top level."
    }

    # Round-trip through JSON: YAML integer keys (owners: 1:) become strings, as the schema expects.
    $json = $yaml | ConvertTo-Json -Depth 10
    $problems = Test-T0Json -Json $json -Schema 'config'
    if ($problems) {
        throw "$file is invalid:`n  $($problems -join "`n  ")"
    }
    $data = $json | ConvertFrom-Json -AsHashtable

    $folder = Split-Path -Parent $file
    $resolve = {
        param($value)
        if ([System.IO.Path]::IsPathRooted($value)) { $value }
        else { [System.IO.Path]::GetFullPath((Join-Path $folder $value)) }
    }
    $breakGlass = @{}
    if ($data.ContainsKey('break_glass')) {
        foreach ($source in $data['break_glass'].Keys) {
            $breakGlass[$source] = @($data['break_glass'][$source] | ForEach-Object { $_.ToLowerInvariant() })
        }
    }
    $outputDir = if ($data.ContainsKey('output_dir')) { $data['output_dir'] } else { 'output' }
    $registersDir = if ($data.ContainsKey('registers_dir')) { $data['registers_dir'] } else { 'registers' }

    [pscustomobject]@{
        PSTypeName         = 'TargetZero.Config'
        Path               = $file
        Organisation       = $data['organisation']
        OutputDirectory    = & $resolve $outputDir
        RegistersDirectory = & $resolve $registersDir
        BreakGlass         = $breakGlass
        Data               = $data
    }
}
