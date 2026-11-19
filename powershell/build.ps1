# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Prepares the TargetZero module for publishing: copies the JSON schemas into the module folder.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$module = Join-Path $PSScriptRoot 'TargetZero'
$target = Join-Path $module 'schemas'
$null = New-Item -ItemType Directory -Path $target -Force
Copy-Item -Path (Join-Path $PSScriptRoot '..' 'schema' '*.schema.json') -Destination $target -Force
Copy-Item -Path (Join-Path $PSScriptRoot '..' 'LICENSE'), (Join-Path $PSScriptRoot '..' 'NOTICE') -Destination $module -Force
Test-ModuleManifest -Path (Join-Path $module 'TargetZero.psd1') | Select-Object Name, Version
