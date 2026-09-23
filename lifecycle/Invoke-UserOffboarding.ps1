<#
.SYNOPSIS
    Offboards a user: blocks sign-in, kills sessions, converts the mailbox, removes access, logs every step.
.DESCRIPTION
    The order matters and this is the order:
      1. Disable the account (blocks new sign-ins)
      2. Revoke refresh tokens and sign-in sessions (kills existing ones, including mobile)
      3. Reset the password to a random value nobody has
      4. Remove all authentication methods except the ones Graph won't allow removing
      5. Convert the mailbox to shared (keeps mail, frees the license) and optionally forward to a manager
      6. Remove from every group and distribution list the account owns membership in
      7. Remove licenses
      8. Hide from the GAL, set an out-of-office if given
      9. Write a JSON record of everything that was done, with before-state, to the log folder
    Every step is individually try-caught and reported, so a failure at step 6 doesn't leave
    the account signed in. -WhatIf shows the plan without touching anything.
    Does not delete the account. That's a separate decision after the retention period.
.NOTES
    Scopes  : User.ReadWrite.All, Directory.ReadWrite.All, Group.ReadWrite.All,
              UserAuthenticationMethod.ReadWrite.All, Organization.Read.All. Exchange: Exchange.ManageAsApp
              or a delegated Exchange Administrator role
    Exit 0  : Every step succeeded
    Exit 1  : One or more steps failed. The log says which. Fix by hand and re-run, it's idempotent
    Output  : One line per step, then the path to the JSON record.
    Untested against a live tenant as committed. Pilot on a test account before using on a person.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [Parameter(Mandatory)] [string]$UserPrincipalName,
    [string]$ForwardMailTo,
    [string]$GrantMailboxAccessTo,
    [string]$AutoReply,
    [string]$LogFolder = '.\offboarding-logs',
    [switch]$KeepLicenses,
    [string]$AppId, [string]$CertificateThumbprint, [string]$ExchangeOrganization
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'User.ReadWrite.All','Directory.ReadWrite.All','Group.ReadWrite.All','UserAuthenticationMethod.ReadWrite.All','Organization.Read.All' -Exchange -AppId $AppId -CertificateThumbprint $CertificateThumbprint -ExchangeOrganization $ExchangeOrganization | Out-Null

$exitCode = 0
$record = [ordered]@{ Tenant = $TenantId; User = $UserPrincipalName; RunBy = (Get-MgContext).Account; Started = (Get-Date).ToString('o'); Steps = @(); Before = $null }
function Step { param([string]$Name, [scriptblock]$Action)
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, $Name)) { $record.Steps += @{ Step = $Name; Result = 'whatif' }; Write-Output "  whatif  $Name"; return }
    try { $r = & $Action; $record.Steps += @{ Step = $Name; Result = 'ok'; Detail = "$r" }; Write-Output "  ok      $Name $(if ($r) { "($r)" })" }
    catch { $record.Steps += @{ Step = $Name; Result = 'FAILED'; Detail = $_.Exception.Message }; Write-Output "  FAILED  $Name : $($_.Exception.Message)"; $script:exitCode = 1 }
}

$u = Get-MgUser -UserId $UserPrincipalName -Property Id,UserPrincipalName,DisplayName,AccountEnabled,AssignedLicenses,Mail
$groups = Get-MgUserMemberOf -UserId $u.Id -All | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
$record.Before = @{ Enabled = $u.AccountEnabled; Licenses = @($u.AssignedLicenses.SkuId); Groups = @($groups | ForEach-Object { $_.AdditionalProperties.displayName }) }
Write-Output "=== Offboarding $($u.DisplayName) <$UserPrincipalName>, tenant $TenantId ==="
Write-Output "  before: enabled=$($u.AccountEnabled) licenses=$($u.AssignedLicenses.Count) groups=$($groups.Count)"

Step 'Disable account' { Update-MgUser -UserId $u.Id -AccountEnabled:$false }
Step 'Revoke sessions and refresh tokens' { Revoke-MgUserSignInSession -UserId $u.Id | Out-Null }
Step 'Reset password to random' {
    $pw = -join ((48..57 + 65..90 + 97..122 + 33,35,36,37,38,42,64) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    Update-MgUser -UserId $u.Id -PasswordProfile @{ Password = $pw; ForceChangePasswordNextSignIn = $true }
    'set'
}
Step 'Remove authentication methods' {
    $removed = 0
    foreach ($m in Get-MgUserAuthenticationMethod -UserId $u.Id) {
        $type = $m.AdditionalProperties.'@odata.type'
        try {
            switch -Wildcard ($type) {
                '*microsoftAuthenticatorAuthenticationMethod' { Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $u.Id -MicrosoftAuthenticatorAuthenticationMethodId $m.Id; $removed++ }
                '*phoneAuthenticationMethod'                  { Remove-MgUserAuthenticationPhoneMethod -UserId $u.Id -PhoneAuthenticationMethodId $m.Id; $removed++ }
                '*fido2AuthenticationMethod'                  { Remove-MgUserAuthenticationFido2Method -UserId $u.Id -Fido2AuthenticationMethodId $m.Id; $removed++ }
                '*softwareOathAuthenticationMethod'           { Remove-MgUserAuthenticationSoftwareOathMethod -UserId $u.Id -SoftwareOathAuthenticationMethodId $m.Id; $removed++ }
                '*emailAuthenticationMethod'                  { Remove-MgUserAuthenticationEmailMethod -UserId $u.Id -EmailAuthenticationMethodId $m.Id; $removed++ }
                '*windowsHelloForBusinessAuthenticationMethod' { Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $u.Id -WindowsHelloForBusinessAuthenticationMethodId $m.Id; $removed++ }
            }
        } catch { Write-Verbose "skip $type : $($_.Exception.Message)" }
    }
    "$removed removed"
}
Step 'Convert mailbox to shared' {
    $mb = Get-Mailbox -Identity $UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $mb) { return 'no mailbox' }
    if ($mb.RecipientTypeDetails -ne 'SharedMailbox') { Set-Mailbox -Identity $UserPrincipalName -Type Shared }
    Set-Mailbox -Identity $UserPrincipalName -HiddenFromAddressListsEnabled $true
    if ($ForwardMailTo) { Set-Mailbox -Identity $UserPrincipalName -ForwardingSmtpAddress $ForwardMailTo -DeliverToMailboxAndForward $true }
    if ($GrantMailboxAccessTo) { Add-MailboxPermission -Identity $UserPrincipalName -User $GrantMailboxAccessTo -AccessRights FullAccess -AutoMapping $true | Out-Null }
    if ($AutoReply) { Set-MailboxAutoReplyConfiguration -Identity $UserPrincipalName -AutoReplyState Enabled -InternalMessage $AutoReply -ExternalMessage $AutoReply }
    'shared' + $(if ($ForwardMailTo) { ", forward to $ForwardMailTo" }) + $(if ($GrantMailboxAccessTo) { ", access to $GrantMailboxAccessTo" })
}
Step 'Remove from groups' {
    $n = 0
    foreach ($g in $groups) {
        try { Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $u.Id; $n++ }
        catch {
            # Dynamic and mail-enabled security or distribution groups need Exchange
            try { Remove-DistributionGroupMember -Identity $g.Id -Member $UserPrincipalName -Confirm:$false -ErrorAction Stop; $n++ }
            catch { Write-Verbose "skip group $($g.AdditionalProperties.displayName)" }
        }
    }
    "$n of $($groups.Count)"
}
if (-not $KeepLicenses) {
    Step 'Remove licenses' {
        $skus = @($u.AssignedLicenses.SkuId)
        if ($skus.Count -gt 0) { Set-MgUserLicense -UserId $u.Id -RemoveLicenses $skus -AddLicenses @() | Out-Null }
        "$($skus.Count) removed"
    }
}

$record.Finished = (Get-Date).ToString('o')
$record.Result = if ($exitCode -eq 0) { 'complete' } else { 'incomplete' }
New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
$logPath = Join-Path $LogFolder ("offboard-{0}-{1}.json" -f ($UserPrincipalName -replace '[@.]', '_'), (Get-Date -Format yyyyMMdd_HHmmss))
$record | ConvertTo-Json -Depth 6 | Set-Content $logPath -Encoding UTF8
Write-Output "  Record: $logPath"
if ($exitCode -eq 0) { Write-Output "RESULT: Offboarding complete. Mailbox retained as shared. Delete the account after the retention period." } else { Write-Output "RESULT: Incomplete. Fix the failed step and re-run." }
exit $exitCode
