function New-InstaboxSshToken {
    <#
    .SYNOPSIS
    Issues a new SSH token for connecting without a keypair (POST /v1/machines/{id}/ssh-tokens).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$Name = 'instabox-ps',

        [ValidateRange(1, 2592000)]
        [int]$TtlSeconds,

        [switch]$NoExpiry
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if ($PSBoundParameters.ContainsKey('TtlSeconds') -and $NoExpiry) {
            throw [System.ArgumentException]::new("-TtlSeconds and -NoExpiry cannot be used together.")
        }

        $body = [ordered]@{}
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $trimmedName = $Name.Trim()
            if ([System.Text.Encoding]::UTF8.GetByteCount($trimmedName) -gt 100) {
                throw [System.ArgumentException]::new("SSH token name must be at most 100 UTF-8 bytes.")
            }
            $body['name'] = $trimmedName
        }
        if ($PSBoundParameters.ContainsKey('TtlSeconds')) {
            $body['ttlSeconds'] = $TtlSeconds
        }
        elseif ($NoExpiry) {
            $body['noExpiry'] = $true
        }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/ssh-tokens" -Body $body
        $tok = $resp.Data

        if ($tok.id -and $tok.token) {
            Set-InstaboxSecretValue -Name "sshToken:$validId`:$($tok.id)" -Value ([string]$tok.token)
            $cfg = Get-InstaboxConfigInternal
            $tracked = [System.Collections.Generic.List[object]]::new()
            foreach ($item in @($cfg.TrackedSshTokens)) {
                if ($item.TokenId -ne $tok.id) { $tracked.Add($item) }
            }
            $tracked.Add([ordered]@{
                MachineId = $validId
                TokenId   = [string]$tok.id
                Name      = [string]$tok.name
                CreatedAt = [DateTimeOffset]::UtcNow.ToString('o')
            })
            $cfg.TrackedSshTokens = $tracked.ToArray()
            Save-InstaboxConfigInternal -Config $cfg
        }

        return $tok
    }
}

function Get-InstaboxSshToken {
    <#
    .SYNOPSIS
    Lists SSH token metadata (and sealed logins in sign-in sessions) for a sandbox (GET /v1/machines/{id}/ssh-tokens).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/machines/$validId/ssh-tokens"
        return @($resp.Data.tokens)
    }
}

function Revoke-InstaboxSshToken {
    <#
    .SYNOPSIS
    Revokes one SSH token (DELETE .../ssh-tokens/{tokenID}) or all tokens (DELETE .../ssh-tokens) of a sandbox.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single', SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(ParameterSetName = 'Single', Mandatory, Position = 1)]
        [string]$TokenId,

        [Parameter(ParameterSetName = 'All', Mandatory)]
        [switch]$All,

        [switch]$Force
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $cfg = Get-InstaboxConfigInternal

        if ($PSCmdlet.ParameterSetName -eq 'All') {
            if (-not $Force -and -not $PSCmdlet.ShouldProcess($validId, 'Revoke ALL SSH tokens and close their active SSH/mosh connections')) {
                return
            }
            $resp = Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/machines/$validId/ssh-tokens"
            $remaining = [System.Collections.Generic.List[object]]::new()
            foreach ($item in @($cfg.TrackedSshTokens)) {
                if ($item.MachineId -eq $validId) {
                    Remove-InstaboxSecretValue -Name "sshToken:$validId`:$($item.TokenId)"
                }
                else {
                    $remaining.Add($item)
                }
            }
            $cfg.TrackedSshTokens = $remaining.ToArray()
            Save-InstaboxConfigInternal -Config $cfg
            return $resp.Data
        }

        if (-not $Force -and -not $PSCmdlet.ShouldProcess("$validId/$TokenId", 'Revoke SSH token')) {
            return
        }
        Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/machines/$validId/ssh-tokens/$([Uri]::EscapeDataString($TokenId))" | Out-Null
        Remove-InstaboxSecretValue -Name "sshToken:$validId`:$TokenId"
        $cfg.TrackedSshTokens = @($cfg.TrackedSshTokens | Where-Object { -not ($_.MachineId -eq $validId -and $_.TokenId -eq $TokenId) })
        Save-InstaboxConfigInternal -Config $cfg
        return [PSCustomObject]@{ Revoked = $true; MachineId = $validId; TokenId = $TokenId }
    }
}

function New-InstaboxSshCertificate {
    <#
    .SYNOPSIS
    Issues a short-lived SSH user certificate for a running sandbox (POST /v1/machines/{id}/connections).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$PublicKey,

        [string]$PrivateKeyPath,

        [ValidateRange(1, 86400)]
        [int]$TtlSeconds = 3600,

        [string]$KnownHostsPath,

        [string]$IdempotencyKey
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $keyPair = $null

        if ([string]::IsNullOrWhiteSpace($PublicKey)) {
            $keyPair = New-InstaboxEphemeralEd25519Keypair -MachineId $validId
            $PublicKey = $keyPair.PublicKey
            $PrivateKeyPath = $keyPair.PrivateKeyPath
        }

        $body = [ordered]@{ publicKey = $PublicKey.Trim() }
        if ($PSBoundParameters.ContainsKey('TtlSeconds')) {
            $body['ttlSeconds'] = $TtlSeconds
        }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/connections" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        $conn = $resp.Data

        $certPath = $null
        if (-not [string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
            $certPath = "$PrivateKeyPath-cert.pub"
            Set-Content -LiteralPath $certPath -Value $conn.certificate -Encoding ascii
        }

        $writtenKnownHosts = $null
        if ($conn.hostTrust -and $conn.hostTrust.publicKey) {
            $writtenKnownHosts = Set-InstaboxKnownHostsAuthority -MachineId $validId -HostName $conn.host -Port ([int]$conn.port) -AuthorityPublicKey $conn.hostTrust.publicKey -KnownHostsPath $KnownHostsPath
        }

        return [PSCustomObject]@{
            Connection      = $conn
            PrivateKeyPath  = $PrivateKeyPath
            CertificatePath = $certPath
            KnownHostsPath  = $writtenKnownHosts
        }
    }
}

function Enter-InstaboxSandbox {
    <#
    .SYNOPSIS
    Prepares SSH config/credentials and opens (or returns) an SSH session to a sandbox.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [ValidateSet('sshToken', 'sshCert', 'terminal')]
        [string]$Mode,

        [string]$ManagedSshConfigPath,

        [string]$MainSshConfigPath,

        [string]$KnownHostsPath,

        [switch]$ConfigureOnly,

        [switch]$Mosh
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $cfg = Get-InstaboxConfigInternal
        if ([string]::IsNullOrWhiteSpace($Mode)) {
            $Mode = [string]$cfg.ConnectMode
        }

        $machine = Get-InstaboxSandbox -Id $validId
        if ($machine.state -eq 'suspended') {
            if ($machine.autoSuspendedAt) {
                $machine = Invoke-InstaboxWake -Id $validId
            }
            else {
                $op = Resume-InstaboxSandbox -Id $validId -Wait
                if ($op.machine) { $machine = $op.machine } else { $machine = Get-InstaboxSandbox -Id $validId }
            }
        }
        elseif ($machine.state -eq 'stopped') {
            $op = Start-InstaboxSandbox -Id $validId -Wait
            if ($op.machine) { $machine = $op.machine } else { $machine = Get-InstaboxSandbox -Id $validId }
        }
        elseif ($machine.state -ne 'running') {
            $op = Start-InstaboxSandbox -Id $validId -Wait
            if ($op.machine) { $machine = $op.machine } else { $machine = Get-InstaboxSandbox -Id $validId }
        }

        $remoteFolder = if ($machine.storage -and $machine.storage.mountPath -eq '/') {
            '/'
        }
        elseif ($machine.guestUser -and $machine.guestUser -ne 'dev') {
            "/home/$($machine.guestUser)"
        }
        else {
            '/data/home'
        }

        if ($Mode -eq 'sshCert') {
            $issued = New-InstaboxSshCertificate -Id $validId -KnownHostsPath $KnownHostsPath
            $conn = $issued.Connection
            $block = Set-InstaboxSshHostBlock -MachineId $validId -SandboxName $machine.name -HostName $conn.host -Port ([int]$conn.port) -User $conn.username -IdentityFile $issued.PrivateKeyPath -CertificateFile $issued.CertificatePath -KnownHostsFile $issued.KnownHostsPath -ManagedConfigPath $ManagedSshConfigPath -MainSshConfigPath $MainSshConfigPath

            $sshCmd = if ([int]$conn.port -eq 22) {
                "ssh -i `"$($issued.PrivateKeyPath)`" -o `"CertificateFile=$($issued.CertificatePath)`" -o `"UserKnownHostsFile=$($issued.KnownHostsPath)`" $($conn.username)@$($conn.host)"
            }
            else {
                "ssh -p $($conn.port) -i `"$($issued.PrivateKeyPath)`" -o `"CertificateFile=$($issued.CertificatePath)`" -o `"UserKnownHostsFile=$($issued.KnownHostsPath)`" $($conn.username)@$($conn.host)"
            }

            if (-not $ConfigureOnly) {
                $sshExe = Get-Command ssh -ErrorAction Stop
                & $sshExe.Source -F $block.ManagedConfigPath $block.PrimaryHost
            }

            return [PSCustomObject]@{
                Mode              = 'sshCert'
                MachineId         = $validId
                SandboxName       = $machine.name
                SshHostAlias      = $block.AliasHost
                ManagedConfigPath = $block.ManagedConfigPath
                Host              = $conn.host
                Port              = $conn.port
                User              = $conn.username
                ExpiresAt         = $conn.expiresAt
                Command           = $sshCmd
                VsCodeRemoteUri   = "vscode-remote://ssh-remote+$($block.AliasHost)$remoteFolder"
            }
        }

        $ttl = [Math]::Min(2592000, [Math]::Max(60, [int]$cfg.TokenTtlSeconds))
        $tok = New-InstaboxSshToken -Id $validId -Name 'instabox-ps' -TtlSeconds $ttl
        $commandToRun = if ($Mosh -and $tok.moshCommand) { $tok.moshCommand } else { $tok.command }

        if ($Mode -eq 'terminal') {
            if (-not $ConfigureOnly) {
                if ($Mosh -and $tok.moshCommand) {
                    $moshExe = Get-Command mosh -ErrorAction Stop
                    $sshOpt = if ([int]$tok.port -eq 22) { 'ssh' } else { "ssh -p $($tok.port)" }
                    & $moshExe.Source "--ssh=$sshOpt" "$($tok.token)@$($tok.host)"
                }
                else {
                    $sshExe = Get-Command ssh -ErrorAction Stop
                    if ([int]$tok.port -eq 22) {
                        & $sshExe.Source "$($tok.token)@$($tok.host)"
                    }
                    else {
                        & $sshExe.Source -p $tok.port "$($tok.token)@$($tok.host)"
                    }
                }
            }
            return [PSCustomObject]@{
                Mode               = 'terminal'
                MachineId          = $validId
                SandboxName        = $machine.name
                Host               = $tok.host
                Port               = $tok.port
                TokenId            = $tok.id
                HostKeyFingerprint = $tok.hostKeyFingerprint
                ExpiresAt          = $tok.expiresAt
                Command            = $commandToRun
            }
        }

        $block = Set-InstaboxSshHostBlock -MachineId $validId -SandboxName $machine.name -HostName $tok.host -Port ([int]$tok.port) -User $tok.token -UseNoneAuth -ManagedConfigPath $ManagedSshConfigPath -MainSshConfigPath $MainSshConfigPath
        if (-not $ConfigureOnly) {
            $sshExe = Get-Command ssh -ErrorAction Stop
            & $sshExe.Source -F $block.ManagedConfigPath $block.PrimaryHost
        }

        return [PSCustomObject]@{
            Mode               = 'sshToken'
            MachineId          = $validId
            SandboxName        = $machine.name
            SshHostAlias       = $block.AliasHost
            ManagedConfigPath  = $block.ManagedConfigPath
            Host               = $tok.host
            Port               = $tok.port
            TokenId            = $tok.id
            HostKeyFingerprint = $tok.hostKeyFingerprint
            ExpiresAt          = $tok.expiresAt
            Command            = $commandToRun
            VsCodeRemoteUri    = "vscode-remote://ssh-remote+$($block.AliasHost)$remoteFolder"
        }
    }
}

function Invoke-InstaboxExec {
    <#
    .SYNOPSIS
    Runs a command (shell cmd or no-shell argv) in a running sandbox (POST /v1/machines/{id}/exec).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Shell')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(ParameterSetName = 'Shell', Mandatory, Position = 1)]
        [string]$Command,

        [Parameter(ParameterSetName = 'Argv', Mandatory)]
        [string[]]$Argv,

        [string]$Cwd,
        [hashtable]$Env,
        [hashtable]$SecretEnv,
        [string]$Stdin,

        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds,

        [switch]$NoHistory,
        [string]$HistoryCommand,
        [switch]$Stream,
        [switch]$NoKeepalive,
        [scriptblock]$OnOutput
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if ($NoHistory -and -not [string]::IsNullOrWhiteSpace($HistoryCommand)) {
            throw [System.ArgumentException]::new("-NoHistory and -HistoryCommand cannot be used together.")
        }

        $cfg = Get-InstaboxConfigInternal
        $effectiveTimeout = if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $TimeoutSeconds } else { [int]$cfg.DefaultExecTimeoutSeconds }
        $body = [ordered]@{}

        if ($PSCmdlet.ParameterSetName -eq 'Shell') {
            if ([string]::IsNullOrEmpty($Command)) {
                throw [System.ArgumentException]::new("-Command cannot be empty.")
            }
            if ([System.Text.Encoding]::UTF8.GetByteCount($Command) -gt 65536 -or $Command.IndexOf([char]0) -ge 0) {
                throw [System.ArgumentException]::new("-Command exceeds 64 KiB or contains NUL bytes.")
            }
            $body['cmd'] = $Command
        }
        else {
            if ($null -eq $Argv -or $Argv.Count -eq 0 -or [string]::IsNullOrEmpty($Argv[0])) {
                throw [System.ArgumentException]::new("-Argv must be non-empty and argv[0] cannot be empty.")
            }
            $body['argv'] = [string[]]$Argv
        }

        if (-not [string]::IsNullOrWhiteSpace($Cwd)) {
            if ([System.Text.Encoding]::UTF8.GetByteCount($Cwd) -gt 4096) {
                throw [System.ArgumentException]::new("-Cwd exceeds 4096 bytes.")
            }
            $body['cwd'] = $Cwd
        }

        if ($Env -and $Env.Count -gt 0) {
            if ($Env.Count -gt 256) {
                throw [System.ArgumentException]::new("-Env supports at most 256 entries.")
            }
            $cleanEnv = [ordered]@{}
            foreach ($ek in $Env.Keys) {
                $k = [string]$ek
                if ($k -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                    throw [System.ArgumentException]::new("Invalid exec environment variable name '$k'.")
                }
                $cleanEnv[$k] = [string]$Env[$ek]
            }
            $body['envs'] = $cleanEnv
        }

        if ($SecretEnv -and $SecretEnv.Count -gt 0) {
            if ($SecretEnv.Count -gt 64) {
                throw [System.ArgumentException]::new("-SecretEnv supports at most 64 entries.")
            }
            if ($script:InstaboxSession.Me -and ($null -eq $script:InstaboxSession.Me.PSObject.Properties['directSecretRefs'] -or -not [bool]$script:InstaboxSession.Me.directSecretRefs)) {
                Write-Warning "Server /v1/me did not advertise directSecretRefs=true; secretEnvs may fail with 400."
            }
            $cleanSecrets = [ordered]@{}
            foreach ($sk in $SecretEnv.Keys) {
                $varName = Assert-InstaboxSecretName -Name ([string]$sk)
                $secretName = Assert-InstaboxSecretName -Name ([string]$SecretEnv[$sk])
                $cleanSecrets[$varName] = $secretName
            }
            $body['secretEnvs'] = $cleanSecrets
        }

        if ($PSBoundParameters.ContainsKey('Stdin')) {
            $stdinBytes = [System.Text.Encoding]::UTF8.GetByteCount($Stdin)
            if ($stdinBytes -gt 1048576) {
                throw [System.ArgumentException]::new("stdin exceeds 1 MiB (1048576 UTF-8 bytes; got $stdinBytes). Upload binary/large input via Send-InstaboxFile first.")
            }
            $body['stdin'] = $Stdin
        }

        if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) {
            $body['timeoutSeconds'] = $TimeoutSeconds
        }
        if ($NoHistory) { $body['noHistory'] = $true }
        if (-not [string]::IsNullOrWhiteSpace($HistoryCommand)) { $body['historyCommand'] = $HistoryCommand }

        $result = Invoke-InstaboxExecRequest -MachineId $validId -Body $body -Stream:$Stream -Keepalive:(-not $NoKeepalive) -TimeoutSeconds $effectiveTimeout -OnOutput $OnOutput

        if ($result.oomKilled) {
            $procName = if ($result.oomKill) { " ($($result.oomKill.process), pid $($result.oomKill.pid))" } else { '' }
            Write-Warning "Command triggered Linux OOM killer$procName."
        }
        if ($result.diskWarning -and $result.diskWarning.level -in @('high', 'critical', 'full')) {
            Write-Warning "Disk warning [$($result.diskWarning.level)] on $($result.diskWarning.mount) ($($result.diskWarning.usedPct)%): $($result.diskWarning.message)"
        }
        if ($result.truncated) {
            Write-Warning "Output exceeded 1 MiB and was truncated; use -Stream for uncapped output."
        }
        if ($result.invalidUtf8) {
            Write-Warning "Output contained non-UTF8 bytes (replaced with U+FFFD); download binary data with Receive-InstaboxFile."
        }

        return $result
    }
}
