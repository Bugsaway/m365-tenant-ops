<#
.SYNOPSIS
    Connects to Microsoft Graph, and optionally Exchange Online, for one tenant with the scopes a script needs.
.DESCRIPTION
    Dot-source this from the report and lifecycle scripts. Handles the two connection styles:
      Interactive - delegated auth, a browser prompt, fine for a one-off run
      App         - certificate-based app registration for scheduled or multi-tenant runs
    Scopes are declared per calling script and passed in, so each one asks for exactly what it
    uses and nothing more. A Global Reader account satisfies every read-only script in this repo.
.NOTES
    Requires: Microsoft.Graph (v2) and, for Exchange scripts, ExchangeOnlineManagement (v3)
    Exit     : Throws on connection failure. Callers handle it.
    Usage    : . .\lib\Connect-Tenant.ps1
               Connect-Tenant -TenantId <id> -Scopes 'User.Read.All','AuditLog.Read.All'
               Connect-Tenant -TenantId <id> -AppId <id> -CertificateThumbprint <thumb> -Scopes ...
#>
function Connect-Tenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TenantId,
        [string[]]$Scopes = @(),
        [string]$AppId,
        [string]$CertificateThumbprint,
        [switch]$Exchange,
        [string]$ExchangeOrganization
    )
    foreach ($m in 'Microsoft.Graph.Authentication') {
        if (-not (Get-Module -ListAvailable $m)) { throw "Module $m not installed. Install-Module Microsoft.Graph -Scope CurrentUser" }
    }
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if ($ctx -and $ctx.TenantId -eq $TenantId -and -not ($Scopes | Where-Object { $_ -notin $ctx.Scopes })) {
        Write-Verbose "Already connected to $TenantId with required scopes"
    }
    elseif ($AppId -and $CertificateThumbprint) {
        Connect-MgGraph -TenantId $TenantId -ClientId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -ErrorAction Stop
    }
    if ($Exchange) {
        if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) { throw "ExchangeOnlineManagement not installed. Install-Module ExchangeOnlineManagement -Scope CurrentUser" }
        $exo = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object State -eq 'Connected'
        if (-not $exo) {
            if ($AppId -and $CertificateThumbprint) {
                if (-not $ExchangeOrganization) { throw "App auth to Exchange needs -ExchangeOrganization (the tenant's onmicrosoft.com domain)" }
                Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $ExchangeOrganization -ShowBanner:$false -ErrorAction Stop
            } else {
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            }
        }
    }
    (Get-MgContext).TenantId
}
