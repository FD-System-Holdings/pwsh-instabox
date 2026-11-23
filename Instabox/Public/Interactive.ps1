function Start-InstaboxApp {
    <#
    .SYNOPSIS
    Launches an interactive terminal menu application covering all instabox milestones (M0-M7).
    #>
    [CmdletBinding()]
    param()

    $showError = {
        param($errRecord)
        $ex = $errRecord.Exception
        Write-Host ""
        if ($ex -is [Instabox.InstaboxApiException]) {
            Write-Host "API Error [$($ex.StatusCode) $($ex.Code)]: $($ex.Message)" -ForegroundColor Red
            if ($ex.Hint) { Write-Host "  Hint: $($ex.Hint)" -ForegroundColor Yellow }
            if ($ex.RequiredScopes -and $ex.RequiredScopes.Count -gt 0) {
                Write-Host "  Required Scopes: $($ex.RequiredScopes -join ', ')" -ForegroundColor Yellow
            }
            if ($ex.OperationId) { Write-Host "  Active Operation ID: $($ex.OperationId)" -ForegroundColor Cyan }
            if ($ex.RetryAfterSeconds) { Write-Host "  Retry after: $($ex.RetryAfterSeconds)s" -ForegroundColor Yellow }
            if ($ex.RequestId) { Write-Host "  Request ID: $($ex.RequestId)" -ForegroundColor DarkGray }
        }
        else {
            Write-Host "Error: $($ex.Message)" -ForegroundColor Red
        }
    }

    $pickSandbox = {
        $boxes = @(Get-InstaboxSandbox)
        if ($boxes.Count -eq 0) {
            Write-Host "No sandboxes found." -ForegroundColor Yellow
            return $null
        }
        for ($i = 0; $i -lt $boxes.Count; $i++) {
            $b = $boxes[$i]
            $readyTxt = if ($b.runtime.hostUnreachable) { 'HOST UNREACHABLE' } elseif ($b.runtime.ready) { 'ready' } else { 'not ready' }
            $specTxt = "$($b.spec.vcpus)c/$($b.spec.memMiB)MiB/$($b.spec.persistentDiskGiB)GiB"
            Write-Host ("  [{0}] {1} ({2}) - {3} ({4}) [{5}]" -f ($i + 1), $b.name, $b.id, $b.state, $readyTxt, $specTxt)
        }
        $pick = Read-Host "Select sandbox number (blank to cancel)"
        if ([string]::IsNullOrWhiteSpace($pick)) { return $null }
        $idx = 0
        if ([int]::TryParse($pick, [ref]$idx) -and $idx -ge 1 -and $idx -le $boxes.Count) {
            return $boxes[$idx - 1]
        }
        Write-Host "Invalid selection." -ForegroundColor Yellow
        return $null
    }

    while ($true) {
        $sess = Get-InstaboxSession
        Write-Host ""
        Write-Host "=== instabox PowerShell Console ===" -ForegroundColor Cyan
        if ($sess.Authenticated) {
            $loginStr = if ($sess.CachedLogin) { $sess.CachedLogin } else { '(authenticated)' }
            $wsTag = if ($sess.WorkspaceOrgId) { " [Workspace: $($sess.WorkspaceOrgId)]" } else { '' }
            Write-Host "Account: $loginStr$wsTag | API: $($sess.ApiBaseUrl)" -ForegroundColor Green
        }
        else {
            Write-Host "Not signed in | API: $($sess.ApiBaseUrl)" -ForegroundColor Yellow
        }
        Write-Host "  1) Sign In / Account Status (M0)"
        Write-Host "  2) Sandboxes & Lifecycle (M1)"
        Write-Host "  3) Connect (SSH / Cert / Terminal) & Exec (M2)"
        Write-Host "  4) Remote Files Explorer & Transfers (M3)"
        Write-Host "  5) Ports (Public / Private HTTP & TCP) (M4)"
        Write-Host "  6) Secrets (Org & Sandbox) (M5)"
        Write-Host "  7) Snapshots & Root FS Browser (M6)"
        Write-Host "  8) Usage, Limits & Monthly Cost (M7)"
        Write-Host "  9) Settings / Sign Out"
        Write-Host "  0) Exit"

        $choice = Read-Host "Choose"
        try {
            switch ($choice) {
                '0' { return }
                '1' {
                    $sub = Read-Host "[A]ccount info (/v1/me), [L]ogin with API key, [B]ack"
                    if ($sub -match '^[Ll]') {
                        $res = Connect-Instabox
                        Write-Host "Signed in as $($res.Login) (org=$($res.Org.id) $($res.Org.tier))" -ForegroundColor Green
                    }
                    elseif ($sub -match '^[Aa]') {
                        $me = Get-InstaboxMe
                        $me | Format-List userId, login, name, email, orgId, inviteRequired, activated, resizeRestart, directSecretRefs
                        if ($me.allowedSpecs) {
                            Write-Host "Allowed specs:" -ForegroundColor Cyan
                            $me.allowedSpecs | Format-Table vcpus, memMiB, persistentDiskGiB -AutoSize
                        }
                    }
                }
                '2' {
                    Write-Host "`nSandboxes:" -ForegroundColor Cyan
                    $boxes = @(Get-InstaboxSandbox)
                    $boxes | Format-Table name, id, state, @{N='Ready';E={$_.runtime.ready}}, @{N='vCPUs';E={$_.spec.vcpus}}, @{N='MemMiB';E={$_.spec.memMiB}}, @{N='DiskGiB';E={$_.spec.persistentDiskGiB}} -AutoSize
                    $act = Read-Host "[N]ew, [S]tart, st[O]p, [P]ause, [R]esume, [W]ake, r[E]size/rename, [F]ork, res[T]ore, [D]elete, [I]nspect, [B]ack"
                    switch -Regex ($act) {
                        '^[Nn]$' {
                            $src = Read-Host "Create from [T]emplate (default) or [S]napshot?"
                            if ($src -match '^[Ss]') {
                                $snaps = @(Get-InstaboxSnapshot | Where-Object { $_.status -eq 'ready' })
                                $snaps | Format-Table id, name, sizeLocked, @{N='Spec';E={"$($_.defaultSpec.vcpus)c/$($_.defaultSpec.memMiB)MiB"}} -AutoSize
                                $sid = Read-Host "Snapshot ID"
                                $sname = Read-Host "Sandbox name (optional)"
                                $op = New-InstaboxSandbox -SnapshotId $sid -Name $sname -Wait
                                Write-Host "Created $($op.machineId): $($op.state)" -ForegroundColor Green
                            }
                            else {
                                $tmps = @(Get-InstaboxTemplate -CreatableOnly -LatestOnly)
                                $tmps | Format-Table id, version, arch, os, gpu -AutoSize
                                $tid = Read-Host "Template ID (default: agent-browser)"
                                if ([string]::IsNullOrWhiteSpace($tid)) { $tid = 'agent-browser' }
                                $sname = Read-Host "Sandbox name (optional)"
                                $op = New-InstaboxSandbox -TemplateId $tid -Name $sname -Wait
                                Write-Host "Created $($op.machineId): $($op.state)" -ForegroundColor Green
                            }
                        }
                        '^[Ss]$' {
                            $b = & $pickSandbox; if ($b) { $rescue = (Read-Host "Rescue mode? [y/N]") -match '^[Yy]'; Start-InstaboxSandbox -Id $b.id -Rescue:$rescue -Wait | Format-List id, state, phase }
                        }
                        '^[Oo]$' { $b = & $pickSandbox; if ($b) { Stop-InstaboxSandbox -Id $b.id -Wait | Format-List id, state } }
                        '^[Pp]$' { $b = & $pickSandbox; if ($b) { Suspend-InstaboxSandbox -Id $b.id -Wait | Format-List id, state } }
                        '^[Rr]$' { $b = & $pickSandbox; if ($b) { Resume-InstaboxSandbox -Id $b.id -Wait | Format-List id, state } }
                        '^[Ww]$' { $b = & $pickSandbox; if ($b) { Invoke-InstaboxWake -Id $b.id | Format-List id, name, state } }
                        '^[Ee]$' {
                            $b = & $pickSandbox
                            if ($b) {
                                $newName = Read-Host "New name (blank to skip)"
                                $newDisk = Read-Host "New persistentDiskGiB (blank to skip)"
                                $newVcpu = Read-Host "New vCPUs (blank to skip)"
                                $newMem = Read-Host "New memMiB (blank to skip)"
                                $restart = (Read-Host "Use apply=restart if running? [y/N]") -match '^[Yy]'
                                $p = @{ Id = $b.id; Wait = $true }
                                if ($newName) { $p['Name'] = $newName }
                                if ($newDisk) { $p['PersistentDiskGiB'] = [int]$newDisk }
                                if ($newVcpu) { $p['Vcpus'] = [int]$newVcpu }
                                if ($newMem) { $p['MemMiB'] = [int]$newMem }
                                if ($restart) { $p['Apply'] = 'restart' }
                                Update-InstaboxSandbox @p | Format-List
                            }
                        }
                        '^[Ff]$' {
                            $b = & $pickSandbox
                            if ($b) {
                                $fname = Read-Host "Fork name (optional)"
                                $p = @{ Id = $b.id; FallbackToSnapshot = $true; Wait = $true }
                                if ($fname) { $p['Name'] = $fname }
                                Copy-InstaboxSandbox @p | Format-List id, machineId, state
                            }
                        }
                        '^[Tt]$' {
                            $b = & $pickSandbox
                            if ($b) {
                                $sid = Read-Host "Snapshot ID (blank for source snapshot)"
                                $p = @{ Id = $b.id; Force = $true; Wait = $true }
                                if ($sid) { $p['SnapshotId'] = $sid }
                                Restore-InstaboxSandbox @p | Format-List id, state
                            }
                        }
                        '^[Dd]$' {
                            $b = & $pickSandbox
                            if ($b) { Remove-InstaboxSandbox -Id $b.id -Wait | Format-List }
                        }
                        '^[Ii]$' {
                            $b = & $pickSandbox
                            if ($b) { Get-InstaboxSandbox -Id $b.id | ConvertTo-Json -Depth 6 }
                        }
                    }
                }
                '3' {
                    $b = & $pickSandbox
                    if ($b) {
                        $sub = Read-Host "[C]onnect SSH, [E]xec command (streaming), [T]okens list/revoke, c[E]rt issue, [B]ack"
                        if ($sub -match '^[Cc]$') {
                            $m = Read-Host "Mode [sshToken / sshCert / terminal] (blank for config default)"
                            $cfgOnly = (Read-Host "Configure only without launching ssh? [y/N]") -match '^[Yy]'
                            $argsMap = @{ Id = $b.id; ConfigureOnly = $cfgOnly }
                            if ($m) { $argsMap['Mode'] = $m }
                            Enter-InstaboxSandbox @argsMap | Format-List
                        }
                        elseif ($sub -match '^[Ee]$') {
                            $cmd = Read-Host "Shell command (bash -lc)"
                            if ($cmd) {
                                $res = Invoke-InstaboxExec -Id $b.id -Command $cmd -Stream
                                Write-Host "`nExitCode: $($res.exitCode) | TimedOut: $($res.timedOut)" -ForegroundColor Cyan
                            }
                        }
                        elseif ($sub -match '^[Tt]$') {
                            Get-InstaboxSshToken -Id $b.id | Format-Table id, name, createdAt, expiresAt, revokedAt -AutoSize
                            $rev = Read-Host "Revoke [id], [ALL], or blank to skip"
                            if ($rev -eq 'ALL') { Revoke-InstaboxSshToken -Id $b.id -All -Force | Format-List }
                            elseif ($rev) { Revoke-InstaboxSshToken -Id $b.id -TokenId $rev -Force | Format-List }
                        }
                    }
                }
                '4' {
                    $b = & $pickSandbox
                    if ($b) {
                        $sub = Read-Host "[L]ist/Read path, [D]ownload, [U]pload, [S]igned upload URL, [M]kdir, [R]emove, [B]ack"
                        switch -Regex ($sub) {
                            '^[Ll]$' {
                                $rp = Read-Host "Remote path (default /data/home)"
                                if (-not $rp) { $rp = '/data/home' }
                                $f = Get-InstaboxFile -Id $b.id -Path $rp
                                if ($f.type -eq 'dir') { $f.entries | Format-Table type, name, size, mode, modTime -AutoSize }
                                else { Write-Host $f.content }
                            }
                            '^[Dd]$' {
                                $rp = Read-Host "Remote file path"
                                $lp = Read-Host "Local destination path"
                                Receive-InstaboxFile -Id $b.id -RemotePath $rp -LocalPath $lp -Resume | Format-List
                            }
                            '^[Uu]$' {
                                $lp = Read-Host "Local file path"
                                $rp = Read-Host "Remote destination path"
                                Send-InstaboxFile -Id $b.id -LocalPath $lp -RemotePath $rp -Parents | Format-List
                            }
                            '^[Ss]$' {
                                $rp = Read-Host "Remote target path"
                                New-InstaboxUploadUrl -Id $b.id -Path $rp -Parents | Format-List
                            }
                            '^[Mm]$' {
                                $rp = Read-Host "Remote directory path"
                                New-InstaboxDirectory -Id $b.id -Path $rp | Format-List
                            }
                            '^[Rr]$' {
                                $rp = Read-Host "Remote path to remove"
                                Remove-InstaboxFile -Id $b.id -Path $rp | Format-List
                            }
                        }
                    }
                }
                '5' {
                    $pl = Get-InstaboxPort
                    Write-Host "Public Ports Enabled: $($pl.enabled)" -ForegroundColor Cyan
                    @($pl.ports) | Format-Table id, machineId, port, name, protocol, access, url, address -AutoSize
                    $act = Read-Host "[E]xpose port, [U]npublish port, [T]oken lookup, [B]ack"
                    if ($act -match '^[Ee]$') {
                        $b = & $pickSandbox
                        if ($b) {
                            $port = [int](Read-Host "Port (1024-65535)")
                            $pname = Read-Host "Label (optional)"
                            $proto = Read-Host "Protocol [http/tcp] (default http)"; if (-not $proto) { $proto = 'http' }
                            $acc = if ($proto -eq 'http') { Read-Host "Access [public/private] (default public)" } else { 'public' }
                            if (-not $acc) { $acc = 'public' }
                            Publish-InstaboxPort -SandboxId $b.id -Port $port -Name $pname -Protocol $proto -Access $acc | Format-List
                        }
                    }
                    elseif ($act -match '^[Uu]$') {
                        $b = & $pickSandbox
                        if ($b) {
                            $port = [int](Read-Host "Port to unpublish")
                            Unpublish-InstaboxPort -SandboxId $b.id -Port $port -Force | Format-List
                        }
                    }
                    elseif ($act -match '^[Tt]$') {
                        $pid = Read-Host "Publication ID"
                        Get-InstaboxPortToken -PortId $pid | Format-List
                    }
                }
                '6' {
                    $sub = Read-Host "[L]ist org secrets, [S]et org secret, [I]mport .env, [D]elete org secret, [M]achine secrets, [B]ack"
                    if ($sub -match '^[Mm]$') {
                        $b = & $pickSandbox
                        if ($b) {
                            $ms = Get-InstaboxSandboxSecret -Id $b.id
                            $ms | Format-List version, secrets, envSecrets, proxy, guest
                            $act = Read-Host "[R]efresh delivery, [U]pdate selections, or Enter"
                            if ($act -match '^[Rr]$') { Sync-InstaboxSandboxSecret -Id $b.id | Format-List }
                            elseif ($act -match '^[Uu]$') {
                                $px = Read-Host "Proxy secrets ('all' or comma-separated names, blank to skip)"
                                $en = Read-Host "Env secrets (comma-separated names, blank to skip)"
                                $p = @{ Id = $b.id }
                                if ($px) { $p['ProxySecrets'] = if ($px -eq 'all') { 'all' } else { @($px -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                                if ($en) { $p['EnvSecrets'] = @($en -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                                Set-InstaboxSandboxSecret @p | Format-List
                            }
                        }
                    }
                    elseif ($sub -match '^[LlIiSsDd]$') {
                        $orgId = Read-Host "Org ID (org_...)"
                        if ($sub -match '^[Ll]$') { Get-InstaboxOrgSecret -OrgId $orgId | Format-Table name, delivery, hosts, version, size, updatedAt -AutoSize }
                        elseif ($sub -match '^[Ss]$') {
                            $n = Read-Host "Secret name"
                            $v = Read-Host "Secret value" -AsSecureString
                            $d = Read-Host "Delivery [proxy/env]"
                            $h = if ($d -eq 'proxy') { @((Read-Host "Allowed hosts (comma-separated, e.g. api.openai.com or *)") -split ',' | ForEach-Object { $_.Trim() }) } else { @() }
                            Set-InstaboxOrgSecret -OrgId $orgId -Name $n -Value $v -Delivery $d -Hosts $h | Format-List
                        }
                        elseif ($sub -match '^[Ii]$') {
                            $fp = Read-Host ".env file path"
                            $d = Read-Host "Delivery [proxy/env]"
                            $h = if ($d -eq 'proxy') { @((Read-Host "Allowed hosts (comma-separated, e.g. *)") -split ',' | ForEach-Object { $_.Trim() }) } else { @() }
                            Import-InstaboxOrgSecret -OrgId $orgId -EnvFile $fp -Delivery $d -Hosts $h | Format-Table name, delivery, version -AutoSize
                        }
                        elseif ($sub -match '^[Dd]$') {
                            $n = Read-Host "Secret name to delete"
                            Remove-InstaboxOrgSecret -OrgId $orgId -Name $n | Format-List
                        }
                    }
                }
                '7' {
                    $snaps = @(Get-InstaboxSnapshot)
                    $snaps | Format-Table id, name, status, sourceMachineId, sizeLocked, @{N='RootGiB';E={[Math]::Round($_.rootSizeBytes/1GB,1)}}, @{N='DataGiB';E={if($_.dataSizeBytes){[Math]::Round($_.dataSizeBytes/1GB,1)}else{'(rootOnly)'}}} -AutoSize
                    $act = Read-Host "[S]ave snapshot, [F]iles browse (root FS only), [D]elete snapshot, [B]ack"
                    if ($act -match '^[Ss]$') {
                        $b = & $pickSandbox
                        if ($b) {
                            $sn = Read-Host "Snapshot name"
                            $ro = (Read-Host "Root system files only (omit /data)? [y/N]") -match '^[Yy]'
                            New-InstaboxSnapshot -SandboxId $b.id -Name $sn -RootOnly:$ro -Wait | Format-List
                        }
                    }
                    elseif ($act -match '^[Ff]$') {
                        $sid = Read-Host "Snapshot ID"
                        $p = Read-Host "Root FS path (default /)"; if (-not $p) { $p = '/' }
                        $f = Get-InstaboxSnapshotFile -Id $sid -Path $p
                        if ($f.type -eq 'dir') { $f.entries | Format-Table type, name, size, mode -AutoSize }
                        else { Write-Host $f.content }
                    }
                    elseif ($act -match '^[Dd]$') {
                        $sid = Read-Host "Snapshot ID"
                        Remove-InstaboxSnapshot -Id $sid | Format-List
                    }
                }
                '8' {
                    $org = Read-Host "Org ID (blank for default)"
                    $u = if ($org) { Get-InstaboxUsage -OrgId $org } else { Get-InstaboxUsage }
                    $u.Summary | Format-List
                    if ($u.cost) {
                        Write-Host "Cost Breakdown:" -ForegroundColor Cyan
                        $u.cost | Format-List periodStart, periodEnd, costUSD, runtimeUSD, storageUSD, egressUSD, gpuUSD, macosUSD, allowanceUSD, creditRemainingUSD, overageUSD, remainingUSD, creditsUSD, billableDiskGiB, allocatedDiskGiB
                    }
                }
                '9' {
                    $sub = Read-Host "[V]iew config, [C]hange ConnectMode/BaseUrl, [L]ogout, [B]ack"
                    if ($sub -match '^[Vv]$') { Get-InstaboxConfig | Format-List }
                    elseif ($sub -match '^[Cc]$') {
                        $cm = Read-Host "ConnectMode [sshToken/sshCert/terminal] (blank keep)"
                        $bu = Read-Host "ApiBaseUrl (blank keep)"
                        $p = @{}
                        if ($cm) { $p['ConnectMode'] = $cm }
                        if ($bu) { $p['ApiBaseUrl'] = $bu }
                        if ($p.Count -gt 0) { Set-InstaboxConfig @p | Format-List }
                    }
                    elseif ($sub -match '^[Ll]$') { Disconnect-Instabox -Confirm:$false | Format-List }
                }
                default { Write-Host "Unknown option." -ForegroundColor Yellow }
            }
        }
        catch {
            & $showError $_
        }
    }
}
