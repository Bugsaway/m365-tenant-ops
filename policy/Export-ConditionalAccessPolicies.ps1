<#
.SYNOPSIS
    Exports every Conditional Access policy to JSON and diffs against a saved baseline.
.DESCRIPTION
    Read-only. Pulls all CA policies with full conditions, grant, and session controls, writes one
    JSON file per policy plus an index, and if a baseline folder is given, reports:
      Added    - policy in the tenant, not in baseline
      Removed  - policy in baseline, not in the tenant
      Changed  - same policy, different content (state, conditions, or controls)
      Disabled - a policy that was enabled in baseline and isn't now. Called out on its own because
                 it's the change an attacker with Global Admin makes first
    Run once with no baseline to create one. Run on a schedule with -BaselinePath to detect drift.
.NOTES
    Scopes  : Policy.Read.All
    Exit 0  : Export written, no drift (or no baseline given)
    Exit 1  : Drift found. Read the diff output
    Output  : <OutputFolder>\<tenant>\<policy-name>.json per policy, _index.json, and the diff.
    Untested against a live tenant as committed. Pilot on one tenant before scheduling.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [string]$OutputFolder = ".\ca-export",
    [string]$BaselinePath,
    [string]$AppId, [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'Policy.Read.All' -AppId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

$out = Join-Path $OutputFolder $TenantId
New-Item -ItemType Directory -Path $out -Force | Out-Null
$policies = Get-MgIdentityConditionalAccessPolicy -All
function Normalize($p) {
    # Drop fields that change on every read so the diff only sees real changes
    $o = $p | Select-Object Id, DisplayName, State, Conditions, GrantControls, SessionControls
    ($o | ConvertTo-Json -Depth 20 -Compress) -replace '"ModifiedDateTime":"[^"]*",?', ''
}
$index = foreach ($p in $policies) {
    $safe = ($p.DisplayName -replace '[\\/:*?"<>|]', '_')
    $json = Normalize $p
    Set-Content -Path (Join-Path $out "$safe.json") -Value ($p | ConvertTo-Json -Depth 20) -Encoding UTF8
    [pscustomobject]@{ Id = $p.Id; DisplayName = $p.DisplayName; State = $p.State; File = "$safe.json"; Hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($json))) -Algorithm SHA256).Hash }
}
$index | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out '_index.json') -Encoding UTF8
Write-Output "=== Conditional Access export, tenant $TenantId ==="
Write-Output "  Policies : $($policies.Count)  enabled $(@($policies | Where-Object State -eq 'enabled').Count)  report-only $(@($policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count)  disabled $(@($policies | Where-Object State -eq 'disabled').Count)"
Write-Output "  Output   : $out"
if (-not $BaselinePath) { Write-Output "RESULT: Exported. Copy this folder to a baseline location and pass -BaselinePath next run."; exit 0 }

$baseIndex = Join-Path $BaselinePath '_index.json'
if (-not (Test-Path $baseIndex)) { Write-Output "Baseline index not found: $baseIndex"; exit 1 }
$base = @{}; foreach ($b in (Get-Content $baseIndex -Raw | ConvertFrom-Json)) { $base[$b.Id] = $b }
$cur  = @{}; foreach ($c in $index) { $cur[$c.Id] = $c }
$drift = @()
foreach ($id in $cur.Keys)  { if (-not $base[$id]) { $drift += [pscustomobject]@{ Change = 'Added'; Policy = $cur[$id].DisplayName; Detail = "state $($cur[$id].State)" } } }
foreach ($id in $base.Keys) { if (-not $cur[$id])  { $drift += [pscustomobject]@{ Change = 'Removed'; Policy = $base[$id].DisplayName; Detail = "was $($base[$id].State)" } } }
foreach ($id in $cur.Keys) {
    if ($base[$id] -and $base[$id].Hash -ne $cur[$id].Hash) {
        $kind = if ($base[$id].State -eq 'enabled' -and $cur[$id].State -ne 'enabled') { 'Disabled' } else { 'Changed' }
        $drift += [pscustomobject]@{ Change = $kind; Policy = $cur[$id].DisplayName; Detail = "$($base[$id].State) -> $($cur[$id].State)" }
    }
}
if ($drift.Count -eq 0) { Write-Output "RESULT: No drift from baseline."; exit 0 }
Write-Output "  Drift:"
$drift | Sort-Object { $_.Change -ne 'Disabled' }, Change | ForEach-Object { Write-Output ("    {0,-9} {1}  ({2})" -f $_.Change, $_.Policy, $_.Detail) }
$drift | Export-Csv (Join-Path $out "_drift-$(Get-Date -Format yyyyMMdd_HHmm).csv") -NoTypeInformation
Write-Output "RESULT: $($drift.Count) change(s) from baseline. Disabled policies first."
exit 1
