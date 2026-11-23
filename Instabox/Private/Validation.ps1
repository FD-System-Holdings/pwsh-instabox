function Assert-InstaboxMachineId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    if ($Id -notmatch '^m_[a-z2-7]{26}$') {
        throw [System.ArgumentException]::new("Invalid sandbox ID '$Id'. Expected canonical format matching ^m_[a-z2-7]{26}$ (e.g. m_...).")
    }
    return $Id
}

function Assert-InstaboxSnapshotId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    if ($Id -notmatch '^(sn|im)_[a-z2-7]{26}$') {
        throw [System.ArgumentException]::new("Invalid snapshot ID '$Id'. Expected format matching ^(sn|im)_[a-z2-7]{26}$.")
    }
    return $Id
}

function Assert-InstaboxResourceName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Kind = 'Resource'
    )

    if ($Name -cnotmatch '^[a-z0-9][a-z0-9-]{0,62}$') {
        throw [System.ArgumentException]::new("Invalid $Kind name '$Name'. Must be 1-63 lowercase letters, digits, or '-', starting with a letter or digit.")
    }
    return $Name
}

function Assert-InstaboxGuestUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GuestUser
    )

    if ($GuestUser -cnotmatch '^[a-z_][a-z0-9_-]{0,31}$') {
        throw [System.ArgumentException]::new("Invalid guestUser '$GuestUser'. Must match ^[a-z_][a-z0-9_-]{0,31}$.")
    }
    $reserved = @('root', 'instabox', 'sudo', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', '_apt', 'nobody', 'messagebus', 'sshd')
    if ($GuestUser -in $reserved -or $GuestUser -like 'systemd-*') {
        throw [System.ArgumentException]::new("guestUser '$GuestUser' is reserved.")
    }
    return $GuestUser
}

function Assert-InstaboxSecretName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$AllowEnvOnly
    )

    if ($Name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') {
        throw [System.ArgumentException]::new("Invalid name '$Name'. Must match ^[A-Za-z_][A-Za-z0-9_]{0,127}$.")
    }

    $reserved = @(
        'BASH_ENV', 'ENV', 'HOME', 'HOSTNAME', 'IFS', 'LOGNAME', 'OLDPWD', 'PATH', 'PWD',
        'SHELL', 'SHLVL', 'USER', 'BASHOPTS', 'BASH_VERSINFO', 'EUID', 'PPID', 'SHELLOPTS',
        'UID', 'TERM', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'SSL_CERT_FILE',
        'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS'
    )
    if ($Name -in $reserved -or $Name.StartsWith('INSTABOX_', [StringComparison]::Ordinal) -or $Name.StartsWith('SSH_', [StringComparison]::Ordinal)) {
        throw [System.ArgumentException]::new("Variable/Secret name '$Name' is reserved.")
    }
    return $Name
}

function Assert-InstaboxSecretHosts {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string[]]$Hosts,

        [Parameter(Mandatory)]
        [ValidateSet('proxy', 'env')]
        [string]$Delivery
    )

    if ($Delivery -eq 'env') {
        if ($null -ne $Hosts -and $Hosts.Count -gt 0) {
            throw [System.ArgumentException]::new("Hosts must be omitted or empty when delivery is 'env'.")
        }
        return [string[]]@()
    }

    if ($null -eq $Hosts -or $Hosts.Count -eq 0) {
        throw [System.ArgumentException]::new("At least one host (or '*') is required when delivery is 'proxy'.")
    }
    if ($Hosts.Count -gt 32) {
        throw [System.ArgumentException]::new("At most 32 hosts are allowed per Secret (got $($Hosts.Count)).")
    }

    $normalized = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in $Hosts) {
        $h = if ($null -eq $raw) { '' } else { $raw.Trim() }
        if ($h -eq '*') {
            $normalized.Add('*')
            continue
        }
        if ([string]::IsNullOrWhiteSpace($h)) {
            throw [System.ArgumentException]::new("Host entry cannot be empty.")
        }
        if ($h.Length -gt 253) {
            throw [System.ArgumentException]::new("Host '$h' exceeds 253 characters.")
        }
        if ($h.EndsWith('.')) {
            throw [System.ArgumentException]::new("Host '$h' must not have a trailing dot.")
        }
        if ($h -match '[:/*\s]') {
            throw [System.ArgumentException]::new("Host '$h' must be an exact ASCII DNS hostname (no scheme, port, path, or partial wildcard).")
        }
        if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') {
            throw [System.ArgumentException]::new("Host '$h' must not be an IP literal.")
        }
        $lower = $h.ToLowerInvariant()
        if ($lower -eq 'localhost' -or $lower.EndsWith('.localhost') -or $lower.EndsWith('.local') -or $lower.EndsWith('.internal')) {
            throw [System.ArgumentException]::new("Host '$h' must not be a local hostname.")
        }
        if ($lower -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$') {
            throw [System.ArgumentException]::new("Host '$h' is not a valid ASCII DNS hostname.")
        }
        $normalized.Add($lower)
    }

    return [string[]]$normalized.ToArray()
}

function Assert-InstaboxSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)]
        [ValidateSet('proxy', 'env')]
        [string]$Delivery
    )

    if ($Value.IndexOf([char]0) -ge 0) {
        throw [System.ArgumentException]::new("Secret value must not contain NUL bytes.")
    }
    $byteLen = [System.Text.Encoding]::UTF8.GetByteCount($Value)
    if ($byteLen -gt 65536) {
        throw [System.ArgumentException]::new("Secret value exceeds 65536 UTF-8 bytes ($byteLen bytes).")
    }
    if ($Delivery -eq 'proxy' -and ($Value.IndexOf("`r") -ge 0 -or $Value.IndexOf("`n") -ge 0)) {
        throw [System.ArgumentException]::new("Proxy Secret values must be valid HTTP header values without CR or LF characters.")
    }
    return $Value
}

function Assert-InstaboxMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metadata
    )

    if ($Metadata.Count -gt 32) {
        throw [System.ArgumentException]::new("Metadata supports at most 32 keys (got $($Metadata.Count)).")
    }
    $clean = [ordered]@{}
    foreach ($k in $Metadata.Keys) {
        $ks = [string]$k
        if ($ks -cnotmatch '^[A-Za-z0-9_.-]{1,64}$') {
            throw [System.ArgumentException]::new("Invalid metadata key '$ks'. Must match ^[A-Za-z0-9_.-]{1,64}$.")
        }
        $vs = [string]$Metadata[$k]
        if ($vs.Length -gt 512) {
            throw [System.ArgumentException]::new("Metadata value for '$ks' exceeds 512 characters.")
        }
        $clean[$ks] = $vs
    }
    $json = $clean | ConvertTo-Json -Compress
    if ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt 8192) {
        throw [System.ArgumentException]::new("Serialized metadata JSON exceeds 8192 bytes.")
    }
    return $clean
}

function Assert-InstaboxPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    if ($Port -lt 1024 -or $Port -gt 65535) {
        throw [System.ArgumentOutOfRangeException]::new('Port', "Port must be between 1024 and 65535 (got $Port).")
    }
    if ($Port -in @(5901, 6768)) {
        throw [System.ArgumentException]::new("Port $Port is reserved (5901=desktop VNC, 6768=Orca).")
    }
    return $Port
}

function Assert-InstaboxFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$NoTrailingSlash
    )

    if (-not $Path.StartsWith('/')) {
        throw [System.ArgumentException]::new("Remote path '$Path' must be an absolute path starting with '/'.")
    }
    $byteLen = [System.Text.Encoding]::UTF8.GetByteCount($Path)
    if ($byteLen -gt 4096) {
        throw [System.ArgumentException]::new("Remote path exceeds 4096 UTF-8 bytes ($byteLen bytes).")
    }
    if ($NoTrailingSlash -and ($Path -eq '/' -or $Path.EndsWith('/'))) {
        throw [System.ArgumentException]::new("File path '$Path' must not end with '/'.")
    }
    return $Path
}

function Assert-InstaboxOctalMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mode
    )

    if ($Mode -notmatch '^0?[0-7]{3}$') {
        throw [System.ArgumentException]::new("Invalid file mode '$Mode'. Expected octal permissions matching ^0?[0-7]{3}$ (e.g. '0644' or '755').")
    }
    return $Mode
}

function Assert-InstaboxIdempotencyKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    if ($Key -notmatch '^[\x21-\x7e]{1,200}$') {
        throw [System.ArgumentException]::new("Invalid Idempotency-Key '$Key'. Must be 1-200 printable ASCII non-whitespace characters.")
    }
    return $Key
}

function Assert-InstaboxApiKeyFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Credential
    )

    $trimmed = $Credential.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw [System.ArgumentException]::new("Credential cannot be empty.")
    }
    if ($trimmed -notmatch '^[\x21-\x7e]+$') {
        throw [System.ArgumentException]::new("Credential contains invalid whitespace or non-ASCII characters.")
    }
    return $trimmed
}

function Test-InstaboxSafeHttpsUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) {
        return $false
    }
    return ($uri.Scheme -eq 'https')
}
