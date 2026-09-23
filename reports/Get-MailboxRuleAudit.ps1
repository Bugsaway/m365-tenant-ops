<#
.SYNOPSIS
    Audits every mailbox for the inbox rule and forwarding patterns used in business email compromise.
.DESCRIPTION
    Read-only. For every user mailbox, pulls inbox rules and mailbox-level forwarding and flags:
      ExternalForward   - a rule or mailbox setting that forwards or redirects outside the tenant
      DeleteOrHide      - a rule that deletes, marks read, or moves mail to RSS Feeds, Archive, Junk,
                          Conversation History, or a folder whose name is a single character
      KeywordTrap       - a rule keyed on subject or body words like invoice, payment, wire, ACH,
                          password, or the practice's bank
      SuspiciousName    - a rule with an empty, single-character, or whitespace-only name
    That combination (hide replies about a payment, forward copies out) is the standard footprint
    of a compromised mailbox, and rules survive a password reset.
.NOTES
    Modules : ExchangeOnlineManagement v3. Exchange scope: Exchange.ManageAsApp for app auth, or
              a delegated Global Reader / View-Only Organization Management role.
    Exit 0  : Nothing flagged
    Exit 1  : Findings. Read the CSV and go look at those mailboxes today
    Output  : CSV with Mailbox, Source (Rule or MailboxForwarding), RuleName, Flags, Detail, Enabled.
    Untested against a live tenant as committed. Pilot on one tenant before scheduling.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [string[]]$InternalDomains,
    [string[]]$Keywords = @('invoice','payment','wire','ach','remit','bank','routing','password','verify','urgent','w-2','w2','payroll','direct deposit'),
    [string[]]$HideFolders = @('RSS Feeds','RSS Subscriptions','Archive','Junk Email','Conversation History','Deleted Items','Notes'),
    [string]$OutputCsv = ".\mailbox-rules-$TenantId-$(Get-Date -Format yyyyMMdd).csv",
    [string]$AppId, [string]$CertificateThumbprint, [string]$ExchangeOrganization
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Connect-Tenant.ps1')
Connect-Tenant -TenantId $TenantId -Scopes 'Domain.Read.All' -Exchange -AppId $AppId -CertificateThumbprint $CertificateThumbprint -ExchangeOrganization $ExchangeOrganization | Out-Null

if (-not $InternalDomains) { $InternalDomains = (Get-AcceptedDomain).DomainName }
function Test-External([string[]]$Addresses) {
    foreach ($a in $Addresses) {
        $addr = ($a -replace '^.*<', '' -replace '>.*$', '' -replace '^SMTP:', '').Trim()
        if ($addr -match '@') { $dom = ($addr -split '@')[-1]; if ($dom -notin $InternalDomains) { return $addr } }
    }
    return $null
}

$mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox
Write-Output "=== Mailbox rule audit, tenant $TenantId, $($mailboxes.Count) mailboxes ==="
$rows = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($mb in $mailboxes) {
    $i++
    if ($i % 25 -eq 0) { Write-Progress -Activity 'Auditing mailboxes' -Status "$i of $($mailboxes.Count)" -PercentComplete ($i * 100 / $mailboxes.Count) }

    # Mailbox-level forwarding
    $fwd = @()
    if ($mb.ForwardingSmtpAddress) { $fwd += $mb.ForwardingSmtpAddress }
    if ($mb.ForwardingAddress)     { $fwd += $mb.ForwardingAddress }
    if ($fwd) {
        $ext = Test-External $fwd
        $rows.Add([pscustomobject]@{ Mailbox = $mb.UserPrincipalName; Source = 'MailboxForwarding'; RuleName = ''; Flags = $(if ($ext) { 'ExternalForward' } else { 'InternalForward' }); Detail = ($fwd -join ', ') + $(if ($mb.DeliverToMailboxAndForward) { ' (keeps copy)' } else { ' (no copy)' }); Enabled = $true })
    }

    # Inbox rules
    $rules = Get-InboxRule -Mailbox $mb.UserPrincipalName -ErrorAction SilentlyContinue
    foreach ($r in $rules) {
        $flags = @(); $detail = @()
        $targets = @($r.ForwardTo + $r.ForwardAsAttachmentTo + $r.RedirectTo) | Where-Object { $_ }
        if ($targets) {
            $ext = Test-External $targets
            if ($ext) { $flags += 'ExternalForward'; $detail += "to $ext" } else { $detail += "internal forward" }
        }
        if ($r.DeleteMessage -or $r.SoftDeleteMessage) { $flags += 'DeleteOrHide'; $detail += 'deletes' }
        if ($r.MarkAsRead) { $flags += 'DeleteOrHide'; $detail += 'marks read' }
        if ($r.MoveToFolder) {
            $folder = ($r.MoveToFolder -split '\\')[-1]
            if ($folder -in $HideFolders -or $folder.Length -le 1) { $flags += 'DeleteOrHide'; $detail += "moves to $folder" }
        }
        $conds = @($r.SubjectContainsWords + $r.BodyContainsWords + $r.SubjectOrBodyContainsWords) | Where-Object { $_ }
        $hit = $conds | Where-Object { $c = $_; $Keywords | Where-Object { $c -like "*$_*" } } | Select-Object -First 3
        if ($hit) { $flags += 'KeywordTrap'; $detail += "keywords: $($hit -join ', ')" }
        if (-not $r.Name -or $r.Name.Trim().Length -le 1) { $flags += 'SuspiciousName' }
        if ($flags) {
            $rows.Add([pscustomobject]@{ Mailbox = $mb.UserPrincipalName; Source = 'Rule'; RuleName = $r.Name; Flags = (($flags | Select-Object -Unique) -join ','); Detail = ($detail -join '; '); Enabled = $r.Enabled })
        }
    }
}
Write-Progress -Activity 'Auditing mailboxes' -Completed
$rows | Export-Csv $OutputCsv -NoTypeInformation

$ext = @($rows | Where-Object Flags -like '*ExternalForward*')
$hide = @($rows | Where-Object Flags -like '*DeleteOrHide*')
Write-Output "  External forwards : $($ext.Count)"
Write-Output "  Delete or hide    : $($hide.Count)"
Write-Output "  Keyword traps     : $(@($rows | Where-Object Flags -like '*KeywordTrap*').Count)"
Write-Output "  Suspicious names  : $(@($rows | Where-Object Flags -like '*SuspiciousName*').Count)"
Write-Output "  Output: $OutputCsv"
$both = @($rows | Where-Object { $_.Flags -like '*ExternalForward*' -and $_.Flags -like '*DeleteOrHide*' })
if ($both) { Write-Output "  $($both.Count) rule(s) both forward out and hide. Treat those mailboxes as compromised until proven otherwise." }
if ($rows.Count -eq 0) { Write-Output "RESULT: Nothing flagged."; exit 0 }
Write-Output "RESULT: $($rows.Count) finding(s)."
exit 1
