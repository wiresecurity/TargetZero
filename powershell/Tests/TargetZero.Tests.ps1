# SPDX-License-Identifier: Apache-2.0
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TargetZero' 'TargetZero.psd1') -Force
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
}

Describe 'Import-T0Config' {
    It 'loads the example config' {
        $config = Import-T0Config -Path (Join-Path $RepoRoot 'config' 'targetzero.example.yaml')
        $config.Organisation | Should -Be 'Example Ltd'
        $config.BreakGlass['m365'].Count | Should -Be 2
        $config.OutputDirectory | Should -Be ([System.IO.Path]::GetFullPath((Join-Path $RepoRoot 'config' 'output')))
    }

    It 'accepts integer owner keys and lowercases break-glass accounts' {
        $path = Join-Path $TestDrive 'targetzero.yaml'
        Set-Content -LiteralPath $path -Value "organisation: T`nowners:`n  1: Alice`nbreak_glass:`n  m365: [BG1@x.onmicrosoft.com]"
        $config = Import-T0Config -Path $path
        $config.Data['owners']['1'] | Should -Be 'Alice'
        $config.BreakGlass['m365'] | Should -Be @('bg1@x.onmicrosoft.com')
    }

    It 'rejects unknown keys' {
        $path = Join-Path $TestDrive 'bad.yaml'
        Set-Content -LiteralPath $path -Value "organisation: T`ntypo_key: 1"
        { Import-T0Config -Path $path } | Should -Throw '*invalid*'
    }

    It 'fails clearly when no config exists' {
        { Import-T0Config -Path (Join-Path $TestDrive 'missing.yaml') } | Should -Throw '*No TargetZero configuration*'
    }
}

Describe 'Export-T0Summary' {
    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $dir
    }

    It 'writes a valid summary with count equal to items' {
        $items = @(@{ id = 'm365:a@x.com/global-administrator'; reason = 'permanent' })
        $path = Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items $items -Tool test `
            -RunDate ([datetime]'2026-11-19')
        Split-Path -Leaf $path | Should -Be '1_m365_admins.summary.json'
        $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $data.count | Should -Be 1
        $data.run_date | Should -Be '2026-11-19'
        $data.items[0].id | Should -Be 'm365:a@x.com/global-administrator'
    }

    It 'writes an empty items array when the count is zero' {
        $path = Export-T0Summary -RunDirectory $dir -Zero 2 -Source m365 -Name mfa -Items @() -Tool test
        $raw = Get-Content -LiteralPath $path -Raw
        $raw | Should -Match '"items": \[\]'
        ($raw | ConvertFrom-Json).count | Should -Be 0
    }

    It 'rejects duplicate ids' {
        $item = @{ id = 'm365:a'; reason = 'r' }
        { Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items @($item, $item) -Tool test } |
            Should -Throw '*duplicate*'
    }

    It 'treats ids that differ only in case as different' {
        $items = @(@{ id = 'm365:A'; reason = 'r' }, @{ id = 'm365:a'; reason = 'r' })
        { Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items $items -Tool test } |
            Should -Not -Throw
    }

    It 'rejects ids with spaces' {
        $items = @(@{ id = 'm365:Global Administrator'; reason = 'r' })
        { Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items $items -Tool test } |
            Should -Throw
    }
}

Describe 'Export-T0Record' {
    It 'writes a header even without records' {
        $path = Export-T0Record -RunDirectory $TestDrive -Zero 1 -Source m365 -Name admins -Records @() -Property id, account
        Get-Content -LiteralPath $path | Should -Be 'id,account'
    }

    It 'keeps the column order of -Property' {
        $rows = @([pscustomobject]@{ account = 'a@x.com'; id = 'm365:a@x.com'; extra = 'dropped' })
        $path = Export-T0Record -RunDirectory $TestDrive -Zero 1 -Source m365 -Name order -Records $rows -Property id, account
        (Get-Content -LiteralPath $path)[0] | Should -Be 'id,account'
    }
}
