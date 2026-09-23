<#
.SYNOPSIS
    Lists enabled users who are not registered for MFA, or only registered with weak methods.
.DESCRIPTION
    Read-only. Uses the authentication methods registration report. Each enabled, non-guest user
    lands in one bucket:
      NotRegistered - no MFA method at all
      WeakOnly      - registered, but every method is SMS or voice
      Registered    - at least one strong method (Authenticator app, FIDO2, Windows Hello, certificate)
    Admin-role holders are flagged separately since they should never be in the first two.
.NOTES
    Scopes  : UserAuthenticationMethod.Read.All, Reports.Read.All, User.Read.All
    Exit 0  : Every enabled user has a strong method
    Exit 1  : Gaps found. Read the CSV
    Output  : CSV with UPN, DisplayName, Bucket, Methods, IsAdmin, DefaultMethod.
    Untested against a live tenant as committed. Pilot on one tenant before scheduling.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [string[]]$StrongMethods = @('microsoftAuthenticatorPush','microsoftAuthenticatorPasswordless','fido2SecurityKey','windowsHelloForBusiness','passKeyDeviceBound','passKeyDeviceBoundAuthenticator','softwareOneTimePasscode','hardwareOneTimePasscode','x509Certificate'),
    [string]$OutputCsv = ".\mfa-gaps-$TenantId-$(Get-Date -Format yyyyMMdd).csv",
    [string]$AppId, [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'UserAuthenticationMethod.Read.All','Reports.Read.All','User.Read.All' -AppId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

$details = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
$enabled = @{}
Get-MgUser -All -Property Id,AccountEnabled,UserType | Where-Object { $_.AccountEnabled -and $_.UserType -ne 'Guest' } | ForEach-Object { $enabled[$_.Id] = $true }

$rows = foreach ($d in $details) {
    if (-not $enabled[$d.Id]) { continue }
    $methods = @($d.MethodsRegistered)
    $strong = @($methods | Where-Object { $_ -in $StrongMethods })
    $bucket = if ($methods.Count -eq 0) { 'NotRegistered' } elseif ($strong.Count -eq 0) { 'WeakOnly' } else { 'Registered' }
    if ($bucket -eq 'Registered') { continue }
    [pscustomobject]@{
        UPN = $d.UserPrincipalName; DisplayName = $d.UserDisplayName; Bucket = $bucket
        Methods = ($methods -join ', '); IsAdmin = $d.IsAdmin; DefaultMethod = $d.DefaultMfaMethod
    }
}
$rows = @($rows | Sort-Object @{ Expression = "IsAdmin"; Descending = $true }, Bucket)
$rows | Export-Csv $OutputCsv -NoTypeInformation
Write-Output "=== MFA registration gaps, tenant $TenantId ==="
Write-Output "  Enabled users   : $($enabled.Count)"
Write-Output "  NotRegistered   : $(@($rows | Where-Object Bucket -eq 'NotRegistered').Count)"
Write-Output "  WeakOnly        : $(@($rows | Where-Object Bucket -eq 'WeakOnly').Count)"
Write-Output "  Admins in gap   : $(@($rows | Where-Object IsAdmin).Count)"
Write-Output "  Output: $OutputCsv"
if ($rows.Count -eq 0) { Write-Output "RESULT: Every enabled user has a strong method."; exit 0 }
Write-Output "RESULT: $($rows.Count) user(s) without strong MFA. Admins first."
exit 1
