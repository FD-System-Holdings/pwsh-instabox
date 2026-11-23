function Ensure-InstaboxSshInclude {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManagedConfigPath,

        [string]$MainSshConfigPath
    )

    $sshDir = Split-Path -Parent $ManagedConfigPath
    if (-not (Test-Path -LiteralPath $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $ManagedConfigPath)) {
        Set-Content -LiteralPath $ManagedConfigPath -Value "# Managed by instabox PowerShell app`n" -Encoding utf8
    }

    if ([string]::IsNullOrWhiteSpace($MainSshConfigPath)) {
        $MainSshConfigPath = Join-Path $sshDir 'config'
    }
    $mainDir = Split-Path -Parent $MainSshConfigPath
    if (-not (Test-Path -LiteralPath $mainDir)) {
        New-Item -ItemType Directory -Path $mainDir -Force | Out-Null
    }

    $normalizedIncludeTarget = $ManagedConfigPath -replace '\\', '/'
    $includeLine = "Include `"$normalizedIncludeTarget`""

    if (-not (Test-Path -LiteralPath $MainSshConfigPath)) {
        Set-Content -LiteralPath $MainSshConfigPath -Value "$includeLine`n" -Encoding utf8
        return
    }

    $existing = Get-Content -LiteralPath $MainSshConfigPath -Raw -Encoding utf8
    if ($null -eq $existing) { $existing = '' }

    $escapedPath = [regex]::Escape($normalizedIncludeTarget)
    $escapedRaw = [regex]::Escape($ManagedConfigPath)
    if ($existing -notmatch "(?im)^\s*Include\s+[""']?(?:$escapedPath|$escapedRaw)[""']?\s*$") {
        $updated = "$includeLine`n`n$existing"
        Set-Content -LiteralPath $MainSshConfigPath -Value $updated -Encoding utf8 -NoNewline
    }
}

function Set-InstaboxSshHostBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [Parameter(Mandatory)]
        [string]$SandboxName,

        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter(Mandatory)]
        [string]$User,

        [string]$IdentityFile,

        [string]$CertificateFile,

        [string]$KnownHostsFile,

        [string]$ManagedConfigPath,

        [string]$MainSshConfigPath,

        [switch]$UseNoneAuth
    )

    if ([string]::IsNullOrWhiteSpace($ManagedConfigPath)) {
        $cfg = Get-InstaboxConfigInternal
        $ManagedConfigPath = [string]$cfg.ManagedSshConfigPath
    }

    Ensure-InstaboxSshInclude -ManagedConfigPath $ManagedConfigPath -MainSshConfigPath $MainSshConfigPath

    $startMarker = "# >>> instabox:$MachineId >>>"
    $endMarker   = "# <<< instabox:$MachineId <<<"

    $aliases = [System.Collections.Generic.List[string]]::new()
    $aliases.Add("instabox-$MachineId")
    if (-not [string]::IsNullOrWhiteSpace($SandboxName) -and "instabox-$SandboxName" -ne "instabox-$MachineId") {
        $aliases.Add("instabox-$SandboxName")
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($startMarker)
    $lines.Add("Host $($aliases -join ' ')")
    $lines.Add("    HostName $HostName")
    $lines.Add("    Port $Port")
    $lines.Add("    User $User")
    $lines.Add("    IdentitiesOnly yes")
    if ($UseNoneAuth) {
        $lines.Add("    PreferredAuthentications none")
        $lines.Add("    PubkeyAuthentication no")
        $lines.Add("    PasswordAuthentication no")
    }
    if (-not [string]::IsNullOrWhiteSpace($IdentityFile)) {
        $lines.Add("    IdentityFile `"$IdentityFile`"")
    }
    if (-not [string]::IsNullOrWhiteSpace($CertificateFile)) {
        $lines.Add("    CertificateFile `"$CertificateFile`"")
    }
    if (-not [string]::IsNullOrWhiteSpace($KnownHostsFile)) {
        $lines.Add("    UserKnownHostsFile `"$KnownHostsFile`"")
    }
    $lines.Add($endMarker)
    $block = ($lines -join "`n") + "`n"

    $content = Get-Content -LiteralPath $ManagedConfigPath -Raw -Encoding utf8
    if ($null -eq $content) { $content = '' }

    $pattern = "(?s)" + [regex]::Escape($startMarker) + ".*?" + [regex]::Escape($endMarker) + "\r?\n?"
    if ($content -match $pattern) {
        $newContent = [regex]::Replace($content, $pattern, $block)
    }
    else {
        $sep = if ($content.Length -gt 0 -and -not $content.EndsWith("`n")) { "`n" } else { "" }
        $newContent = $content + $sep + $block
    }

    Set-Content -LiteralPath $ManagedConfigPath -Value $newContent -Encoding utf8 -NoNewline
    return [PSCustomObject]@{
        PrimaryHost       = $aliases[0]
        AliasHost         = if ($aliases.Count -gt 1) { $aliases[1] } else { $aliases[0] }
        ManagedConfigPath = $ManagedConfigPath
    }
}

function Remove-InstaboxSshHostBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [string]$ManagedConfigPath
    )

    if ([string]::IsNullOrWhiteSpace($ManagedConfigPath)) {
        $cfg = Get-InstaboxConfigInternal
        $ManagedConfigPath = [string]$cfg.ManagedSshConfigPath
    }

    if (-not (Test-Path -LiteralPath $ManagedConfigPath)) {
        return
    }

    $content = Get-Content -LiteralPath $ManagedConfigPath -Raw -Encoding utf8
    if ([string]::IsNullOrEmpty($content)) { return }

    $startMarker = "# >>> instabox:$MachineId >>>"
    $endMarker   = "# <<< instabox:$MachineId <<<"
    $pattern = "(?s)" + [regex]::Escape($startMarker) + ".*?" + [regex]::Escape($endMarker) + "\r?\n?"
    $updated = [regex]::Replace($content, $pattern, '')
    Set-Content -LiteralPath $ManagedConfigPath -Value $updated -Encoding utf8 -NoNewline
}

function Set-InstaboxKnownHostsAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter(Mandatory)]
        [string]$AuthorityPublicKey,

        [string]$KnownHostsPath
    )

    if ([string]::IsNullOrWhiteSpace($KnownHostsPath)) {
        $stateDir = Get-InstaboxStateDir
        $KnownHostsPath = Join-Path $stateDir 'known_hosts'
    }

    $dir = Split-Path -Parent $KnownHostsPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $hostSpec = if ($Port -eq 22) { $HostName } else { "[$HostName]:$Port" }
    $marker = "# instabox:$MachineId"
    $entry = "@cert-authority $hostSpec $($AuthorityPublicKey.Trim()) $marker`n"

    $existing = if (Test-Path -LiteralPath $KnownHostsPath) {
        Get-Content -LiteralPath $KnownHostsPath -Raw -Encoding utf8
    }
    else { '' }
    if ($null -eq $existing) { $existing = '' }

    $filteredLines = @($existing -split "\r?\n" | Where-Object { $_ -ne '' -and $_ -notlike "*$marker" })
    $out = if ($filteredLines.Count -gt 0) { ($filteredLines -join "`n") + "`n$entry" } else { $entry }
    Set-Content -LiteralPath $KnownHostsPath -Value $out -Encoding utf8 -NoNewline
    return $KnownHostsPath
}

function Clear-InstaboxKnownHostsEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [string]$HostName,

        [int]$Port = 0,

        [string]$KnownHostsPath
    )

    $paths = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($KnownHostsPath)) {
        $paths.Add($KnownHostsPath)
    }
    else {
        $stateDir = Get-InstaboxStateDir
        $paths.Add((Join-Path $stateDir 'known_hosts'))
        $paths.Add((Join-Path (Join-Path $HOME '.ssh') 'known_hosts'))
    }

    $marker = "# instabox:$MachineId"
    $hostPattern = if (-not [string]::IsNullOrWhiteSpace($HostName)) {
        if ($Port -gt 0 -and $Port -ne 22) { "[$HostName]:$Port" } else { $HostName }
    } else { $null }

    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $lines = Get-Content -LiteralPath $p -Encoding utf8
        $kept = $lines | Where-Object {
            if ($_ -like "*$marker") { return $false }
            if ($hostPattern -and ($_ -like "$hostPattern *" -or $_ -like "@cert-authority $hostPattern *")) { return $false }
            return $true
        }
        $out = if ($kept) { (@($kept) -join "`n") + "`n" } else { '' }
        Set-Content -LiteralPath $p -Value $out -Encoding utf8 -NoNewline
    }
}

function Set-InstaboxPrivateKeyAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath
    )

    if (-not (Test-Path -LiteralPath $KeyPath)) { return }
    if ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT')) {
        try {
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls.exe $KeyPath /inheritance:r /grant:r "${user}:(R,W)" *> $null
        }
        catch {
            Write-InstaboxLog -Level 'WARN' -Message "Failed setting Windows ACL on SSH key '$KeyPath': $($_.Exception.Message)"
        }
    }
    else {
        chmod 600 $KeyPath 2>$null
    }
}

function New-InstaboxEphemeralEd25519Keypair {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [string]$OutputDir
    )

    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = Join-Path (Get-InstaboxStateDir) 'keys'
    }
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $keyBase = Join-Path $OutputDir "id_ed25519_$MachineId"
    $pubPath = "$keyBase.pub"
    if (Test-Path -LiteralPath $keyBase) { Remove-Item -LiteralPath $keyBase -Force }
    if (Test-Path -LiteralPath $pubPath) { Remove-Item -LiteralPath $pubPath -Force }

    $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $keygen) {
        throw [System.InvalidOperationException]::new("ssh-keygen was not found on PATH; cannot generate Ed25519 SSH keypair automatically. Pass -PublicKey explicitly or install OpenSSH Client.")
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new($keygen.Source)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    foreach ($arg in @('-t', 'ed25519', '-N', '', '-f', $keyBase, '-C', "instabox-$MachineId", '-q')) {
        $psi.ArgumentList.Add($arg)
    }

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        throw [System.InvalidOperationException]::new("ssh-keygen failed with exit code $($proc.ExitCode): $stderr $stdout")
    }

    Set-InstaboxPrivateKeyAcl -KeyPath $keyBase
    $pubKey = (Get-Content -LiteralPath $pubPath -Raw -Encoding ascii).Trim()

    return [PSCustomObject]@{
        PrivateKeyPath = $keyBase
        PublicKeyPath  = $pubPath
        PublicKey      = $pubKey
    }
}
