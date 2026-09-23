<#
.SYNOPSIS
    Reconciles purchased licenses against assignments and flags waste.
.DESCRIPTION
    Read-only. For every SKU: purchased, assigned, available, and how many are assigned to
    accounts that are disabled or haven't signed in within $StaleDays. That last number is the
    monthly spend with nobody behind it. Also lists SKUs at or over capacity, which is where the
    next new hire fails to get a mailbox.
.NOTES
    Scopes  : Organization.Read.All, User.Read.All, AuditLog.Read.All
    Exit 0  : No waste and no SKU over capacity
    Exit 1  : Licensed disabled or stale accounts, or a SKU at capacity. Read the CSVs
    Output  : Two CSVs. sku-summary (one row per SKU) and license-waste (one row per wasted seat).
    Untested against a live tenant as committed. Pilot on one tenant before scheduling.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [int]$StaleDays = 60,
    [string]$OutputFolder = '.',
    [string]$AppId, [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'Organization.Read.All','User.Read.All','AuditLog.Read.All' -AppId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

$stamp = Get-Date -Format yyyyMMdd
$skus = Get-MgSubscribedSku -All | Where-Object { $_.CapabilityStatus -eq 'Enabled' }
$skuName = @{}; foreach ($s in $skus) { $skuName[$s.SkuId] = $s.SkuPartNumber }
$staleCut = (Get-Date).AddDays(-$StaleDays)
$users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,AssignedLicenses,SignInActivity -ConsistencyLevel eventual | Where-Object { $_.AssignedLicenses.Count -gt 0 }
$hasSignIn = [bool]($users | Where-Object { $_.SignInActivity.LastSignInDateTime -or $_.SignInActivity.LastNonInteractiveSignInDateTime } | Select-Object -First 1)
if (-not $hasSignIn) { Write-Output "No sign-in activity exposed (no Entra ID P1 or P2). Stale detection off, reporting disabled accounts only." }

$waste = foreach ($u in $users) {
    $last = @($u.SignInActivity.LastSignInDateTime, $u.SignInActivity.LastNonInteractiveSignInDateTime) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $reason = if (-not $u.AccountEnabled) { 'Disabled' } elseif (-not $hasSignIn) { $null } elseif ($last -and $last -lt $staleCut) { "NoSignIn>$StaleDays d" } elseif (-not $last) { 'NeverSignedIn' } else { $null }
    if ($reason) {
        foreach ($l in $u.AssignedLicenses) {
            [pscustomobject]@{ UPN = $u.UserPrincipalName; DisplayName = $u.DisplayName; Sku = $skuName[$l.SkuId]; Reason = $reason; LastSignIn = $last }
        }
    }
}
$waste = @($waste)
$summary = foreach ($s in $skus) {
    $wasted = @($waste | Where-Object Sku -eq $s.SkuPartNumber).Count
    $avail = $s.PrepaidUnits.Enabled - $s.ConsumedUnits
    [pscustomobject]@{
        Sku = $s.SkuPartNumber; Purchased = $s.PrepaidUnits.Enabled; Assigned = $s.ConsumedUnits
        Available = $avail; Wasted = $wasted; AtCapacity = ($avail -le 0)
    }
}
$summary = @($summary | Sort-Object Wasted -Descending)
$summary | Export-Csv (Join-Path $OutputFolder "sku-summary-$TenantId-$stamp.csv") -NoTypeInformation
$waste   | Export-Csv (Join-Path $OutputFolder "license-waste-$TenantId-$stamp.csv") -NoTypeInformation

Write-Output "=== License reconciliation, tenant $TenantId ==="
$summary | ForEach-Object { Write-Output ("  {0,-40} bought {1,4} used {2,4} free {3,4} wasted {4,3}{5}" -f $_.Sku, $_.Purchased, $_.Assigned, $_.Available, $_.Wasted, $(if ($_.AtCapacity) { '  AT CAPACITY' } else { '' })) }
$atCap = @($summary | Where-Object AtCapacity).Count
Write-Output "  Wasted seats total: $($waste.Count)   SKUs at capacity: $atCap"
if ($waste.Count -eq 0 -and $atCap -eq 0) { Write-Output "RESULT: Clean."; exit 0 }
Write-Output "RESULT: Review license-waste CSV. Reclaim before buying more."
exit 1
