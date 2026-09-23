# m365-tenant-ops

Microsoft 365 and Entra ID operations for an MSP managing multiple tenants. Read-only audits that ticket on findings, a Conditional Access drift check against a saved baseline, and an offboarding runbook that closes the door in the right order and logs every step. Built on the Microsoft Graph PowerShell SDK v2 and ExchangeOnlineManagement v3.

Same conventions as [msp-powershell-ops](https://github.com/Bugsaway/msp-powershell-ops): detect first, exit 0 is clean, exit 1 is a ticket, every finding goes to CSV, every script declares the exact scopes it needs.

## Status

Scripts are written against the current SDK cmdlet surface and pass a parse check, convention tests, and PSScriptAnalyzer on every push. They have not yet been run against a production tenant from this repo. Pilot each one on a single tenant with a Global Reader account before scheduling it. The read-only reports can't hurt anything. Run the offboarding script against a test account before a person.

## Requirements

- PowerShell 7.2 or later (Windows PowerShell 5.1 parses it, but the Graph SDK is built for 7)
- `Install-Module Microsoft.Graph, ExchangeOnlineManagement -Scope CurrentUser`
- Interactive: a Global Reader sign-in for the audits, Global Administrator or the User Administrator plus Exchange Administrator pair for offboarding
- Unattended: an app registration per tenant with a certificate and the application permissions each script lists in its `.NOTES`
- Get-StaleAccountReport needs Entra ID P1 or P2 in the tenant. Without it, sign-in activity isn't exposed, and the script stops and says so rather than reporting everyone as never signed in

## How to use

Every script takes `-TenantId`. Add `-AppId` and `-CertificateThumbprint` for app auth, and `-ExchangeOrganization tenant.onmicrosoft.com` for anything that touches Exchange under app auth.

```powershell
# One tenant, interactive
.\reports\Get-MailboxRuleAudit.ps1 -TenantId <guid>

# Every tenant in tenants.json, unattended
.\Invoke-AllTenants.ps1 -Script .\reports\Get-MailboxRuleAudit.ps1

# Conditional Access: create a baseline, then check against it
.\policy\Export-ConditionalAccessPolicies.ps1 -TenantId <guid> -OutputFolder .\baselines
.\policy\Export-ConditionalAccessPolicies.ps1 -TenantId <guid> -BaselinePath .\baselines\<guid>

# Offboarding, plan first
.\lifecycle\Invoke-UserOffboarding.ps1 -TenantId <guid> -UserPrincipalName user@domain -ForwardMailTo manager@domain -WhatIf
```

Copy `tenants.sample.json` to `tenants.json` and fill it in. `tenants.json` is gitignored, along with every output folder.

## Layout

```
m365-tenant-ops/
  lib/         Connect-Tenant.ps1, the shared connection helper every script dot-sources
  reports/     Read-only audits. Exit 1 on findings
  policy/      Conditional Access export and drift check
  lifecycle/   Offboarding
  baselines/   Where CA baselines live (contents gitignored)
  tests/       Pester conventions, no tenant needed
  Invoke-AllTenants.ps1   Loops any script over tenants.json
```

## Scripts

| Script | What it does | Scopes | Exit 1 when |
|---|---|---|---|
| reports/Get-StaleAccountReport.ps1 | Enabled accounts with no sign-in in 90 days, and accounts created 30+ days ago that never signed in. Licensed ones sorted first | User.Read.All, AuditLog.Read.All | Any stale or never-signed-in account |
| reports/Get-MfaRegistrationGaps.ps1 | Enabled users with no MFA method, or only SMS and voice. Admin role holders flagged | UserAuthenticationMethod.Read.All, Reports.Read.All, User.Read.All | Any user without a strong method |
| reports/Get-LicenseReconciliation.ps1 | Per SKU: purchased, assigned, available, and seats on disabled or stale accounts. SKUs at capacity flagged | Organization.Read.All, User.Read.All, AuditLog.Read.All | Wasted seats or a SKU at capacity |
| reports/Get-MailboxRuleAudit.ps1 | Every mailbox's inbox rules and forwarding, flagged for external forward, delete or hide, keyword traps, and blank rule names. The BEC footprint | Exchange: Global Reader or Exchange.ManageAsApp | Any finding |
| policy/Export-ConditionalAccessPolicies.ps1 | Exports every CA policy to JSON. With a baseline, reports added, removed, changed, and disabled policies. Disabled is called out first | Policy.Read.All | Any drift |
| lifecycle/Invoke-UserOffboarding.ps1 | Disable, revoke sessions, random password, strip auth methods, mailbox to shared with optional forward and delegate, out of groups, licenses off, JSON record. `-WhatIf` supported. Never deletes | User.ReadWrite.All, Directory.ReadWrite.All, Group.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, Exchange admin | Any step fails |
| Invoke-AllTenants.ps1 | Runs any of the above across tenants.json, one output folder per tenant, rolled-up exit code | Whatever the target declares | Any tenant exits 1 |

## What the mailbox rule audit is looking for

A compromised mailbox almost always has the same three things: a rule that forwards or redirects mail outside the tenant, a rule that hides the replies (delete, mark read, or move to RSS Feeds, Archive, or a folder named with a single character), and a keyword condition on invoice, payment, wire, ACH, or the like. The rules survive a password reset, which is why a reset alone doesn't end the incident. A mailbox that hits both ExternalForward and DeleteOrHide on the same rule should be treated as compromised until proven otherwise.

## Offboarding order, and why

1. Disable the account. Blocks new sign-ins.
2. Revoke sessions and refresh tokens. Kills the sessions that already exist, including phones.
3. Random password. Belt and suspenders for step 1.
4. Remove authentication methods. So a re-enable by mistake doesn't hand the old phone MFA back.
5. Mailbox to shared. Keeps the mail, drops the license, optional forward and delegate for the manager.
6. Out of every group. Distribution lists through Exchange, everything else through Graph.
7. Licenses off.
8. JSON record with before-state, so what happened is auditable and reversible by hand.

Deletion is deliberately not in the script. That's a separate decision after the retention period.

## Configuration

All parameters, no config blocks. Thresholds (`-StaleDays`, `-GraceDays`), the strong-method list, the BEC keyword list, and the hide-folder list are all parameters with defaults shown in each script's `param` block. `-ExcludeUpnPatterns` on the stale report defaults to service and break-glass patterns.

## Testing

`Invoke-Pester -Path ./tests` runs without a tenant. It checks that every script parses, has help with scopes and an exit contract, takes `-TenantId`, connects through the shared helper, and contains no GUIDs, onmicrosoft domains, or secrets. The workflow runs the same on every push.

## License

MIT. See [LICENSE](LICENSE).

## Author

Roy Burns
[linkedin.com/in/roy-burns-633942190](https://www.linkedin.com/in/roy-burns-633942190/)
