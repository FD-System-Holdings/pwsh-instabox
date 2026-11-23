function Connect-Instabox {
    <#
    .SYNOPSIS
    Signs in to instabox with an API key (or bearer token) and verifies it via GET /v1/me.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        $ApiKey,

        [string]$BaseUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        $cfg = Get-InstaboxConfigInternal
        $cfg.ApiBaseUrl = $BaseUrl.TrimEnd('/')
        Save-InstaboxConfigInternal -Config $cfg
    }

    $plainKey = $null
    if ($null -eq $ApiKey) {
        $sec = Read-Host -Prompt 'Enter Instabox API Key (ibk_...)' -AsSecureString
        $plainKey = [System.Net.NetworkCredential]::new('', $sec).Password
    }
    elseif ($ApiKey -is [System.Security.SecureString]) {
        $plainKey = [System.Net.NetworkCredential]::new('', $ApiKey).Password
    }
    else {
        $plainKey = [string]$ApiKey
    }

    $validated = Assert-InstaboxApiKeyFormat -Credential $plainKey
    $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/me' -ExplicitToken $validated
    $me = $resp.Data

    Set-InstaboxSecretValue -Name 'apiKey' -Value $validated
    $script:InstaboxSession.Me = $me
    $script:InstaboxSession.MeFetchedAt = [DateTimeOffset]::UtcNow

    if ($me.disabled) {
        Write-Warning "This account has been disabled by an administrator."
    }
    if ($me.exportOnly) {
        Write-Warning "This session is export-only (account disabled). Most API endpoints will return 403 account_disabled."
    }
    if ($me.inviteRequired -and -not $me.activated) {
        $msg = "Account has not passed the invite gate yet (inviteRequired=true, activated=false). Endpoints other than /v1/me will return 403 invite_required."
        if ($me.waitlist) {
            if ($me.waitlist.position) { $msg += " Waitlist position: $($me.waitlist.position)." }
            if ($me.waitlist.referralUrl) { $msg += " Referral URL: $($me.waitlist.referralUrl)." }
        }
        if ($me.paidActivation) {
            $msg += " Paid workspace activation is available in the dashboard."
        }
        Write-Warning $msg
    }

    $isWorkspaceKey = -not [string]::IsNullOrWhiteSpace([string]$me.orgId)
    return [PSCustomObject]@{
        UserId         = $me.userId
        Login          = $me.login
        Name           = $me.name
        Email          = $me.email
        IsWorkspaceKey = $isWorkspaceKey
        WorkspaceOrgId = $me.orgId
        Org            = $me.org
        Workspaces     = $me.workspaces
        InviteRequired = [bool]$me.inviteRequired
        Activated      = [bool]$me.activated
        AllowedSpecs   = $me.allowedSpecs
        Me             = $me
    }
}

function Disconnect-Instabox {
    <#
    .SYNOPSIS
    Signs out, optionally revoking extension-tracked SSH tokens, and clears stored secrets.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$KeepSshTokens
    )

    if (-not $PSCmdlet.ShouldProcess('instabox session', 'Sign out and clear local credentials')) {
        return
    }

    $cfg = Get-InstaboxConfigInternal
    $revokedCount = 0
    if (-not $KeepSshTokens -and $cfg.TrackedSshTokens) {
        $apiKey = Get-InstaboxSecretValue -Name 'apiKey'
        if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
            foreach ($entry in @($cfg.TrackedSshTokens)) {
                try {
                    Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/machines/$($entry.MachineId)/ssh-tokens/$($entry.TokenId)" -AllowRetry $false | Out-Null
                    $revokedCount++
                }
                catch {
                    Write-InstaboxLog -Level 'WARN' -Message "Could not revoke tracked SSH token $($entry.TokenId) on $($entry.MachineId): $($_.Exception.Message)"
                }
            }
        }
        $cfg.TrackedSshTokens = @()
        Save-InstaboxConfigInternal -Config $cfg
    }

    Clear-InstaboxSecrets
    $script:InstaboxSession.Me = $null
    $script:InstaboxSession.MeFetchedAt = $null

    return [PSCustomObject]@{
        SignedOut       = $true
        SshTokensRevoked = $revokedCount
    }
}

function Get-InstaboxMe {
    <#
    .SYNOPSIS
    Retrieves the signed-in user profile, orgs, allowed specs, and server capability flags (GET /v1/me).
    #>
    [CmdletBinding()]
    param(
        [switch]$Cached
    )

    if ($Cached -and $null -ne $script:InstaboxSession.Me) {
        return $script:InstaboxSession.Me
    }

    $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/me'
    $script:InstaboxSession.Me = $resp.Data
    $script:InstaboxSession.MeFetchedAt = [DateTimeOffset]::UtcNow
    return $resp.Data
}

function Get-InstaboxSession {
    <#
    .SYNOPSIS
    Shows local authentication status without calling the remote API or exposing raw secrets.
    #>
    [CmdletBinding()]
    param()

    $cfg = Get-InstaboxConfigInternal
    $hasKey = -not [string]::IsNullOrWhiteSpace((Get-InstaboxSecretValue -Name 'apiKey'))
    $me = $script:InstaboxSession.Me

    return [PSCustomObject]@{
        Authenticated  = $hasKey
        ApiBaseUrl     = $cfg.ApiBaseUrl
        StateDir       = (Get-InstaboxStateDir)
        CachedLogin    = if ($me) { $me.login } else { $null }
        WorkspaceOrgId = if ($me) { $me.orgId } else { $null }
        MeFetchedAt    = $script:InstaboxSession.MeFetchedAt
    }
}

function Get-InstaboxConfig {
    <#
    .SYNOPSIS
    Gets the current instabox PowerShell application configuration.
    #>
    [CmdletBinding()]
    param()

    return (Get-InstaboxConfigInternal)
}

function Set-InstaboxConfig {
    <#
    .SYNOPSIS
    Updates one or more instabox PowerShell application settings.
    #>
    [CmdletBinding()]
    param(
        [string]$ApiBaseUrl,
        [string]$DefaultOrg,
        [ValidateSet('sshToken', 'sshCert', 'terminal')]
        [string]$ConnectMode,
        [string]$ManagedSshConfigPath,
        [ValidateRange(1, 2592000)]
        [int]$TokenTtlSeconds,
        [string]$DefaultTemplate,
        [Nullable[bool]]$StreamExec,
        [ValidateRange(1, 600)]
        [int]$DefaultExecTimeoutSeconds,
        [ValidateRange(1, 16)]
        [int]$FsMaxConcurrency,
        [ValidateRange(5, 3600)]
        [int]$PollIntervalSeconds
    )

    $cfg = Get-InstaboxConfigInternal
    if ($PSBoundParameters.ContainsKey('ApiBaseUrl')) { $cfg.ApiBaseUrl = $ApiBaseUrl.TrimEnd('/') }
    if ($PSBoundParameters.ContainsKey('DefaultOrg')) { $cfg.DefaultOrg = $DefaultOrg }
    if ($PSBoundParameters.ContainsKey('ConnectMode')) { $cfg.ConnectMode = $ConnectMode }
    if ($PSBoundParameters.ContainsKey('ManagedSshConfigPath')) { $cfg.ManagedSshConfigPath = $ManagedSshConfigPath }
    if ($PSBoundParameters.ContainsKey('TokenTtlSeconds')) { $cfg.TokenTtlSeconds = $TokenTtlSeconds }
    if ($PSBoundParameters.ContainsKey('DefaultTemplate')) { $cfg.DefaultTemplate = $DefaultTemplate }
    if ($PSBoundParameters.ContainsKey('StreamExec') -and $null -ne $StreamExec) { $cfg.StreamExec = [bool]$StreamExec }
    if ($PSBoundParameters.ContainsKey('DefaultExecTimeoutSeconds')) { $cfg.DefaultExecTimeoutSeconds = $DefaultExecTimeoutSeconds }
    if ($PSBoundParameters.ContainsKey('FsMaxConcurrency')) { $cfg.FsMaxConcurrency = $FsMaxConcurrency }
    if ($PSBoundParameters.ContainsKey('PollIntervalSeconds')) { $cfg.PollIntervalSeconds = $PollIntervalSeconds }

    Save-InstaboxConfigInternal -Config $cfg
    return $cfg
}
