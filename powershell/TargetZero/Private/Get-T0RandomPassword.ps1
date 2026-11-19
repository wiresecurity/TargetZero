# SPDX-License-Identifier: Apache-2.0
function Get-T0RandomPassword {
    <#
    .SYNOPSIS
        Random password from a cryptographic random source. Letters, digits and symbols.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([ValidateRange(16, 256)][int]$Length = 64)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-.:=?@_~'.ToCharArray()
    $chars = for ($i = 0; $i -lt $Length; $i++) { $alphabet[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)] }
    return -join $chars
}
