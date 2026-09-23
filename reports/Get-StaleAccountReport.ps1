<#
.SYNOPSIS
    Lists enabled accounts that haven't signed in within a threshold, and accounts that never have.
.DESCRIPTION
    Read-only. Pulls every user with signInActivity from Graph and buckets each enabled account:
      NeverSignedIn - created more than $GraceDays ago, no interactive or non-interactive sign-in on record
      Stale         - last sign-in (either kind) older than $StaleDays
    Disabled accounts, guests (optional), and accounts in the exclusion list are skipped. Licensed
    stale accounts are flagged separately because they cost money every month they sit there.
.PARAMETER TenantId
    Tenant to report on. Loop over a list for multi-tenant.
.NOTES
    Scopes  : User.Read.All, AuditLog.Read.All
    Requires: Entra ID P1 or P2 in the tenant. Without it signInActivity is empty and the script stops with exit 1
    Exit 0  : Report written, nothing over threshold
    Exit 1  : Stale or never-signed-in enabled accounts found. Read the CSV
    Output  : CSV with UPN, DisplayName, Bucket, LastSignIn, Created, Licensed, AccountType.
    Untested against a live tenant as committed. Pilot on one tenant before scheduling.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [int]$StaleDays = 90,
    [int]$GraceDays = 30,
    [string[]]$ExcludeUpnPatterns = @('*svc-*', '*service*', '*admin*', '*break*glass*'),
    [switch]$IncludeGuests,
    [string]$OutputCsv = ".\stale-accounts-$TenantId-$(Get-Date -Format yyyyMMdd).csv",
    [string]$AppId, [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'User.Read.All','AuditLog.Read.All' -AppId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

$staleCut = (Get-Date).AddDays(-$StaleDays)
$graceCut = (Get-Date).AddDays(-$GraceDays)
$users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,CreatedDateTime,UserType,AssignedLicenses,SignInActivity -ConsistencyLevel eventual
if (-not ($users | Where-Object { $_.SignInActivity.LastSignInDateTime -or $_.SignInActivity.LastNonInteractiveSignInDateTime } | Select-Object -First 1)) {
    Write-Output "No sign-in activity returned for any user. This tenant has no Entra ID P1 or P2, so signInActivity isn't exposed. Stopping rather than reporting everyone as never signed in."
    exit 1
}

$rows = foreach ($u in $users) {
    if (-not $u.AccountEnabled) { continue }
    if (-not $IncludeGuests -and $u.UserType -eq 'Guest') { continue }
    $skip = $false; foreach ($p in $ExcludeUpnPatterns) { if ($u.UserPrincipalName -like $p) { $skip = $true; break } }
    if ($skip) { continue }
    $last = @($u.SignInActivity.LastSignInDateTime, $u.SignInActivity.LastNonInteractiveSignInDateTime) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $bucket = $null
    if (-not $last) { if ($u.CreatedDateTime -lt $graceCut) { $bucket = 'NeverSignedIn' } }
    elseif ($last -lt $staleCut) { $bucket = 'Stale' }
    if ($bucket) {
        [pscustomobject]@{
            UPN = $u.UserPrincipalName; DisplayName = $u.DisplayName; Bucket = $bucket
            LastSignIn = $last; Created = $u.CreatedDateTime
            Licensed = [bool]$u.AssignedLicenses.Count; AccountType = $u.UserType
        }
    }
}
$rows = @($rows | Sort-Object Licensed -Descending)
$rows | Export-Csv $OutputCsv -NoTypeInformation
Write-Output "=== Stale accounts, tenant $TenantId ==="
Write-Output "  Users evaluated : $($users.Count)"
Write-Output "  NeverSignedIn   : $(@($rows | Where-Object Bucket -eq 'NeverSignedIn').Count)"
Write-Output "  Stale > $StaleDays d   : $(@($rows | Where-Object Bucket -eq 'Stale').Count)"
Write-Output "  Of which licensed: $(@($rows | Where-Object Licensed).Count)"
Write-Output "  Output: $OutputCsv"
if ($rows.Count -eq 0) { Write-Output "RESULT: No stale accounts."; exit 0 }
Write-Output "RESULT: $($rows.Count) account(s) to review. Licensed ones first."
exit 1
