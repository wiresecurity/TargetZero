# SPDX-License-Identifier: Apache-2.0
Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
$script:ModuleVersion = '0.2.0'

foreach ($folder in 'Private', 'Public') {
    $path = Join-Path $PSScriptRoot $folder
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter '*.ps1' | ForEach-Object { . $_.FullName }
    }
}
