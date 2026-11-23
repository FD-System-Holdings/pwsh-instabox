$script:InstaboxSession = [ordered]@{
    Me              = $null
    MeFetchedAt     = $null
    HttpClient      = $null
    RetryDelayScale = 1.0
    FsSemaphore     = $null
    FsSemaphoreSize = 0
}

function Get-InstaboxStateDir {
    [CmdletBinding()]
    param()

    $dir = if (-not [string]::IsNullOrWhiteSpace($env:INSTABOX_PS_HOME)) {
        $env:INSTABOX_PS_HOME
    }
    else {
        Join-Path $HOME '.instabox-ps'
    }

    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Get-InstaboxDefaultConfig {
    [CmdletBinding()]
    param()

    $sshDir = Join-Path $HOME '.ssh'
    return [ordered]@{
        ApiBaseUrl                = 'https://api.instabox.sh'
        DefaultOrg                = ''
        ConnectMode               = 'sshToken'
        ManagedSshConfigPath      = (Join-Path $sshDir 'instabox_config')
        TokenTtlSeconds           = 604800
        DefaultTemplate           = 'agent-browser'
        StreamExec                = $true
        DefaultExecTimeoutSeconds = 60
        FsMaxConcurrency          = 6
        PollIntervalSeconds       = 15
        TrackedSshTokens          = @()
    }
}

function Get-InstaboxConfigInternal {
    [CmdletBinding()]
    param()

    $stateDir = Get-InstaboxStateDir
    $configPath = Join-Path $stateDir 'config.json'
    $defaults = Get-InstaboxDefaultConfig

    if (-not (Test-Path -LiteralPath $configPath)) {
        return [PSCustomObject]$defaults
    }

    try {
        $raw = Get-Content -LiteralPath $configPath -Raw -Encoding utf8
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [PSCustomObject]$defaults
        }
        $parsed = $raw | ConvertFrom-Json -AsHashtable
        foreach ($key in $defaults.Keys) {
            if (-not $parsed.ContainsKey($key)) {
                $parsed[$key] = $defaults[$key]
            }
        }
        if ($null -eq $parsed['TrackedSshTokens']) {
            $parsed['TrackedSshTokens'] = @()
        }
        return [PSCustomObject]$parsed
    }
    catch {
        Write-InstaboxLog -Level 'WARN' -Message "Failed to read config.json; using defaults: $($_.Exception.Message)"
        return [PSCustomObject]$defaults
    }
}

function Save-InstaboxConfigInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $stateDir = Get-InstaboxStateDir
    $configPath = Join-Path $stateDir 'config.json'
    $json = $Config | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $configPath -Value $json -Encoding utf8
}

function Get-InstaboxAesKey {
    [CmdletBinding()]
    param()

    $stateDir = Get-InstaboxStateDir
    $keyPath = Join-Path $stateDir '.secret.key'
    if (Test-Path -LiteralPath $keyPath) {
        $b64 = (Get-Content -LiteralPath $keyPath -Raw -Encoding ascii).Trim()
        return [Convert]::FromBase64String($b64)
    }

    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    Set-Content -LiteralPath $keyPath -Value ([Convert]::ToBase64String($bytes)) -Encoding ascii -NoNewline
    if (-not $IsWindows) {
        chmod 600 $keyPath 2>$null
    }
    return $bytes
}

function Protect-InstaboxSecretString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PlainText
    )

    $secure = ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    if ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT')) {
        return ($secure | ConvertFrom-SecureString)
    }
    $key = Get-InstaboxAesKey
    return ($secure | ConvertFrom-SecureString -Key $key)
}

function Unprotect-InstaboxSecretString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CipherText
    )

    if ([string]::IsNullOrEmpty($CipherText)) {
        return ''
    }
    $secure = if ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT')) {
        ConvertTo-SecureString -String $CipherText
    }
    else {
        $key = Get-InstaboxAesKey
        ConvertTo-SecureString -String $CipherText -Key $key
    }
    $cred = [System.Net.NetworkCredential]::new('', $secure)
    return $cred.Password
}

function Get-InstaboxSecretMap {
    [CmdletBinding()]
    param()

    $stateDir = Get-InstaboxStateDir
    $secretsPath = Join-Path $stateDir 'secrets.json'
    if (-not (Test-Path -LiteralPath $secretsPath)) {
        return @{}
    }
    $raw = Get-Content -LiteralPath $secretsPath -Raw -Encoding utf8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @{}
    }
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Save-InstaboxSecretMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Map
    )

    $stateDir = Get-InstaboxStateDir
    $secretsPath = Join-Path $stateDir 'secrets.json'
    $json = $Map | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $secretsPath -Value $json -Encoding utf8
    if (-not $IsWindows) {
        chmod 600 $secretsPath 2>$null
    }
}

function Get-InstaboxSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $map = Get-InstaboxSecretMap
    if (-not $map.ContainsKey($Name)) {
        return $null
    }
    return Unprotect-InstaboxSecretString -CipherText ([string]$map[$Name])
}

function Set-InstaboxSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $map = Get-InstaboxSecretMap
    $map[$Name] = Protect-InstaboxSecretString -PlainText $Value
    Save-InstaboxSecretMap -Map $map
}

function Remove-InstaboxSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $map = Get-InstaboxSecretMap
    if ($map.ContainsKey($Name)) {
        $map.Remove($Name) | Out-Null
        Save-InstaboxSecretMap -Map $map
    }
}

function Clear-InstaboxSecrets {
    [CmdletBinding()]
    param()

    $stateDir = Get-InstaboxStateDir
    $secretsPath = Join-Path $stateDir 'secrets.json'
    if (Test-Path -LiteralPath $secretsPath) {
        Remove-Item -LiteralPath $secretsPath -Force
    }
}

function Protect-InstaboxLogText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $redacted = $Text
    # Redact token prefixes
    $redacted = [regex]::Replace($redacted, 'ibk_[A-Za-z0-9_-]+', 'ibk_[REDACTED]')
    $redacted = [regex]::Replace($redacted, 'iba_[A-Za-z0-9_-]+', 'iba_[REDACTED]')
    $redacted = [regex]::Replace($redacted, 'ibssh_[A-Za-z0-9_-]+', 'ibssh_[REDACTED]')
    $redacted = [regex]::Replace($redacted, 'ibp_[A-Za-z0-9_-]+', 'ibp_[REDACTED]')
    $redacted = [regex]::Replace($redacted, 'ibpv_[A-Za-z0-9_-]+', 'ibpv_[REDACTED]')

    # Redact HTTP auth headers
    $redacted = [regex]::Replace(
        $redacted,
        '(?i)(X-API-Key|Authorization)\s*([:=])\s*(?:(Bearer|Port)\s+)?([^\r\n,;"'']+)',
        {
            param($m)
            $hdr = $m.Groups[1].Value
            $sep = $m.Groups[2].Value
            $scheme = $m.Groups[3].Value
            if ($scheme) {
                return "$hdr$sep $scheme [REDACTED]"
            }
            return "$hdr$sep [REDACTED]"
        }
    )

    # Redact query parameters (_token= / token=)
    $redacted = [regex]::Replace($redacted, '(?i)([?&](?:_token|token)=)[^&\s"''`]+', '$1[REDACTED]')
    return $redacted
}

function Write-InstaboxLog {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory)]
        [string]$Message
    )

    $safe = Protect-InstaboxLogText -Text $Message
    $ts = [DateTimeOffset]::UtcNow.ToString('o')
    $line = "[$ts] [$Level] $safe"

    try {
        $stateDir = Get-InstaboxStateDir
        $logPath = Join-Path $stateDir 'instabox.log'
        Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
    }
    catch {
        # Ignore logging I/O errors so API calls never fail because of log file locks
    }

    if ($Level -eq 'DEBUG') {
        Write-Debug $line
    }
    else {
        Write-Verbose $line
    }
}

function Get-InstaboxFsSemaphore {
    [CmdletBinding()]
    param()

    $cfg = Get-InstaboxConfigInternal
    $limit = [Math]::Max(1, [int]$cfg.FsMaxConcurrency)
    if ($null -eq $script:InstaboxSession.FsSemaphore -or $script:InstaboxSession.FsSemaphoreSize -ne $limit) {
        $script:InstaboxSession.FsSemaphore = [System.Threading.SemaphoreSlim]::new($limit, $limit)
        $script:InstaboxSession.FsSemaphoreSize = $limit
    }
    return $script:InstaboxSession.FsSemaphore
}
