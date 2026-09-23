<#
.SYNOPSIS
    Runs one script against every tenant in tenants.json and rolls up the exit codes.
.DESCRIPTION
    Loops the tenant list, runs the named script with -TenantId plus app auth when the tenant
    entry has an AppId and CertificateThumbprint, and switches into a per-tenant output folder
    first so each script's default output paths land in the right place. Exit 1 if any tenant
    exited 1, so one scheduled run can ticket across the fleet.
.NOTES
    Scopes  : Whatever the target script declares. This just loops
    Exit 0  : Every tenant exited 0
    Exit 1  : At least one tenant exited 1 or threw. Listed at the end
    Output  : Each tenant's own output under <OutputRoot>\<TenantName>\
.EXAMPLE
    .\Invoke-AllTenants.ps1 -Script .\reports\Get-MailboxRuleAudit.ps1
    .\Invoke-AllTenants.ps1 -Script .\policy\Export-ConditionalAccessPolicies.ps1 -ScriptArgs @{ BaselinePath = 'C:\Baselines' }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Script,
    [string]$Tenants = '.\tenants.json',
    [string]$OutputRoot = '.\output',
    [hashtable]$ScriptArgs = @{}
)
$ErrorActionPreference = 'Continue'
if (-not (Test-Path $Tenants)) { Write-Output "Tenant list not found: $Tenants. Copy tenants.sample.json to tenants.json and fill it in."; exit 1 }
$scriptPath = (Resolve-Path $Script).Path
$list = Get-Content $Tenants -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$failed = @()
foreach ($t in $list) {
    $folder = Join-Path (Resolve-Path $OutputRoot) ($t.Name -replace '[^\w-]', '_')
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    Write-Output "=== $($t.Name) ==="
    $a = @{ TenantId = $t.TenantId } + $ScriptArgs
    if ($t.AppId -and $t.CertificateThumbprint) { $a.AppId = $t.AppId; $a.CertificateThumbprint = $t.CertificateThumbprint }
    if ($t.ExchangeOrganization) { $a.ExchangeOrganization = $t.ExchangeOrganization }
    Push-Location $folder
    try {
        & $scriptPath @a
        if ($LASTEXITCODE -ne 0) { $failed += $t.Name }
    }
    catch { Write-Output "  ERROR: $($_.Exception.Message)"; $failed += $t.Name }
    finally { Pop-Location; Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
}
if ($failed) { Write-Output "RESULT: Findings or errors in: $($failed -join ', ')"; exit 1 }
Write-Output "RESULT: All tenants clean."
exit 0
