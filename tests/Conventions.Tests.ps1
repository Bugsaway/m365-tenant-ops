<#
.SYNOPSIS
    Convention tests. No tenant needed. Checks structure, help, scopes, and that nothing is hardcoded.
#>
BeforeDiscovery {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:Scripts  = Get-ChildItem $RepoRoot -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.Name -notin 'Connect-Tenant.ps1','Invoke-AllTenants.ps1' }
}
Describe 'Script: <_.Name>' -ForEach $Scripts {
    BeforeAll {
        $file = $_
        $content = Get-Content $file.FullName -Raw
        $help = if ($content -match '(?s)<#(.*?)#>') { $matches[1] } else { '' }
        $code = (($content -replace '(?s)<#.*?#>', '') -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
    It 'parses' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }
    It 'has SYNOPSIS, DESCRIPTION, NOTES' {
        $help | Should -Match '\.SYNOPSIS'; $help | Should -Match '\.DESCRIPTION'; $help | Should -Match '\.NOTES'
    }
    It 'NOTES declares the Graph scopes or Exchange role it needs' {
        $help | Should -Match '(?i)Scopes\s*:|Modules\s*:'
    }
    It 'NOTES documents the exit contract' {
        $help | Should -Match '(?i)Exit\s*[01]'
    }
    It 'takes TenantId as a mandatory parameter' {
        $code | Should -Match '\[Parameter\(Mandatory\)\]\s*\[string\]\$TenantId'
    }
    It 'connects through the shared helper with explicit scopes' {
        $code | Should -Match 'Connect-Tenant\.ps1'
        $code | Should -Match 'Connect-Tenant\s+-TenantId'
    }
    It 'contains no tenant IDs, GUIDs, or onmicrosoft domains' {
        $code | Should -Not -Match '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        $code | Should -Not -Match '(?i)\.onmicrosoft\.com'
    }
    It 'contains no secrets' {
        $code | Should -Not -Match '(?i)(ClientSecret|password)\s*=\s*[''"][^''"]{8,}'
    }
}
Describe 'State-changing scripts' {
    It 'Invoke-UserOffboarding supports -WhatIf' {
        (Get-Content "$RepoRoot\lifecycle\Invoke-UserOffboarding.ps1" -Raw) | Should -Match 'SupportsShouldProcess'
    }
    It 'Invoke-UserOffboarding never deletes the account' {
        $c = Get-Content "$RepoRoot\lifecycle\Invoke-UserOffboarding.ps1" -Raw
        $c | Should -Not -Match 'Remove-MgUser\b'
    }
}
