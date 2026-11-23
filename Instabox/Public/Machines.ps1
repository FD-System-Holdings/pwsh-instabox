function Get-InstaboxSandbox {
    <#
    .SYNOPSIS
    Lists sandboxes across your orgs (GET /v1/machines) or gets one sandbox by ID (GET /v1/machines/{id}).
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(ParameterSetName = 'ById', Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(ParameterSetName = 'List')]
        [hashtable]$Metadata,

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, 1000)]
        [int]$PageSize,

        [Parameter(ParameterSetName = 'List')]
        [string]$Cursor,

        [Parameter(ParameterSetName = 'List')]
        [switch]$NoAutoPaginate
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $validId = Assert-InstaboxMachineId -Id $Id
            $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/machines/$validId"
            return $resp.Data
        }

        $metaFilters = $null
        if ($Metadata -and $Metadata.Count -gt 0) {
            $metaFilters = [System.Collections.Generic.List[string]]::new()
            foreach ($k in $Metadata.Keys) {
                $metaFilters.Add("$k`:$($Metadata[$k])")
            }
        }

        $all = [System.Collections.Generic.List[object]]::new()
        $currentCursor = $Cursor

        do {
            $q = @{}
            if (-not [string]::IsNullOrWhiteSpace($currentCursor)) { $q['cursor'] = $currentCursor }
            if ($PSBoundParameters.ContainsKey('PageSize')) { $q['limit'] = $PageSize }
            if ($metaFilters) { $q['metadata'] = $metaFilters.ToArray() }

            $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/machines' -Query $q
            $page = $resp.Data
            if ($page.machines) {
                foreach ($m in $page.machines) {
                    $all.Add($m)
                }
            }
            $currentCursor = $page.nextCursor
        } while (-not $NoAutoPaginate -and -not [string]::IsNullOrWhiteSpace($currentCursor))

        if ($NoAutoPaginate) {
            return [PSCustomObject]@{
                Machines   = $all.ToArray()
                NextCursor = $currentCursor
            }
        }
        return $all.ToArray()
    }
}

function New-InstaboxSandbox {
    <#
    .SYNOPSIS
    Creates a new sandbox from a template or snapshot (POST /v1/machines).
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$TemplateId,
        [string]$TemplateVersion,
        [string]$SnapshotId,
        [ValidateRange(1, 128)]
        [int]$Vcpus,
        [ValidateRange(1, 1048576)]
        [int]$MemMiB,
        [ValidateSet('running', 'stopped')]
        [string]$DesiredState,
        [hashtable]$Metadata,
        [ValidateRange(60, 86400)]
        [int]$ArchiveSeconds,
        [ValidateRange(60, 86400)]
        [int]$DeleteAfterSeconds,
        [ValidateRange(-1, 2147483647)]
        [int]$MaxRunMinutes,
        [int]$AutoSuspendAfterSeconds,
        [switch]$DisableVault,
        $ProxySecrets,
        [string[]]$EnvSecrets,
        [object[]]$DirectSecrets,
        [hashtable]$Env,
        [string]$Pool,
        [string]$GuestUser,
        [switch]$FailFast,
        [switch]$AcceptMinimumLease,
        [string]$Model,
        [string]$Gpu,
        [string]$OrgId,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    if (-not [string]::IsNullOrWhiteSpace($TemplateId) -and -not [string]::IsNullOrWhiteSpace($SnapshotId)) {
        throw [System.ArgumentException]::new("Specify at most one of -TemplateId and -SnapshotId.")
    }
    if ($PSBoundParameters.ContainsKey('EnvSecrets') -and $PSBoundParameters.ContainsKey('DirectSecrets')) {
        throw [System.ArgumentException]::new("-EnvSecrets and -DirectSecrets cannot be sent together.")
    }

    $body = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace($Name)) { $body['name'] = Assert-InstaboxResourceName -Name $Name -Kind 'sandbox' }
    if (-not [string]::IsNullOrWhiteSpace($TemplateId)) { $body['templateId'] = $TemplateId }
    if (-not [string]::IsNullOrWhiteSpace($TemplateVersion)) { $body['templateVersion'] = $TemplateVersion }
    if (-not [string]::IsNullOrWhiteSpace($SnapshotId)) { $body['snapshotId'] = Assert-InstaboxSnapshotId -Id $SnapshotId }
    if ($PSBoundParameters.ContainsKey('Vcpus')) { $body['vcpus'] = $Vcpus }
    if ($PSBoundParameters.ContainsKey('MemMiB')) { $body['memMiB'] = $MemMiB }
    if (-not [string]::IsNullOrWhiteSpace($DesiredState)) { $body['desiredState'] = $DesiredState }
    if ($PSBoundParameters.ContainsKey('Metadata') -and $null -ne $Metadata) { $body['metadata'] = Assert-InstaboxMetadata -Metadata $Metadata }
    if ($PSBoundParameters.ContainsKey('ArchiveSeconds')) { $body['archiveSeconds'] = $ArchiveSeconds }
    if ($PSBoundParameters.ContainsKey('DeleteAfterSeconds')) { $body['deleteAfterSeconds'] = $DeleteAfterSeconds }
    if ($PSBoundParameters.ContainsKey('MaxRunMinutes')) { $body['maxRunMinutes'] = $MaxRunMinutes }
    if ($PSBoundParameters.ContainsKey('AutoSuspendAfterSeconds')) { $body['autoSuspendAfterSeconds'] = $AutoSuspendAfterSeconds }
    if ($DisableVault) { $body['vault'] = $false }

    if ($PSBoundParameters.ContainsKey('ProxySecrets') -and $null -ne $ProxySecrets) {
        if ($ProxySecrets -is [string] -and $ProxySecrets -eq 'all') {
            $body['secrets'] = 'all'
        }
        else {
            $arr = @($ProxySecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
            $body['secrets'] = [string[]]$arr
        }
    }
    if ($PSBoundParameters.ContainsKey('EnvSecrets') -and $null -ne $EnvSecrets) {
        $arr = @($EnvSecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
        $body['envSecrets'] = [string[]]$arr
    }
    if ($PSBoundParameters.ContainsKey('DirectSecrets') -and $null -ne $DirectSecrets) {
        if ($script:InstaboxSession.Me -and ($null -eq $script:InstaboxSession.Me.PSObject.Properties['directSecretRefs'] -or -not [bool]$script:InstaboxSession.Me.directSecretRefs)) {
            Write-Warning "Server /v1/me did not advertise directSecretRefs=true; directSecrets may be rejected with 400."
        }
        $body['directSecrets'] = @($DirectSecrets)
    }
    if ($PSBoundParameters.ContainsKey('Env') -and $null -ne $Env) {
        if ($Env.Count -gt 128) {
            throw [System.ArgumentException]::new("Sandbox env supports at most 128 entries.")
        }
        $cleanEnv = [ordered]@{}
        foreach ($ek in $Env.Keys) {
            $validKey = Assert-InstaboxSecretName -Name ([string]$ek)
            $ev = [string]$Env[$ek]
            if ($ev.IndexOf([char]0) -ge 0) {
                throw [System.ArgumentException]::new("Env variable '$validKey' value must not contain NUL bytes.")
            }
            $cleanEnv[$validKey] = $ev
        }
        $body['env'] = $cleanEnv
    }

    if (-not [string]::IsNullOrWhiteSpace($Pool)) { $body['pool'] = $Pool }
    if (-not [string]::IsNullOrWhiteSpace($GuestUser)) { $body['guestUser'] = Assert-InstaboxGuestUser -GuestUser $GuestUser }
    if ($FailFast) { $body['failFast'] = $true }
    if ($AcceptMinimumLease) { $body['acceptMinimumLease'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($Model)) { $body['model'] = $Model }
    if (-not [string]::IsNullOrWhiteSpace($Gpu)) { $body['gpu'] = $Gpu }
    if (-not [string]::IsNullOrWhiteSpace($OrgId)) { $body['orgId'] = $OrgId }

    $resp = Invoke-InstaboxRequest -Method 'POST' -Path '/v1/machines' -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
    $op = $resp.Data
    if ($Wait) {
        return (Wait-InstaboxOperation -Id $op.id)
    }
    return $op
}

function Update-InstaboxSandbox {
    <#
    .SYNOPSIS
    Renames, resizes, or updates settings on a sandbox (PATCH /v1/machines/{id}).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$Name,
        [ValidateRange(1, 32)]
        [int]$Vcpus,
        [ValidateRange(512, 131072)]
        [int]$MemMiB,
        [ValidateRange(1, 1024)]
        [int]$PersistentDiskGiB,
        [ValidateRange(1, 1024)]
        [int]$RootDiskGiB,
        [hashtable]$Metadata,
        [int]$AutoSuspendAfterSeconds,
        [ValidateRange(-1, 2147483647)]
        [int]$MaxRunMinutes,
        [switch]$DisableVault,
        [switch]$CancelScheduled,
        [ValidateSet('restart')]
        [string]$Apply,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if ($Apply -eq 'restart' -and $PSBoundParameters.ContainsKey('MaxRunMinutes') -and $MaxRunMinutes -eq 0) {
            throw [System.ArgumentException]::new("maxRunMinutes: 0 cannot be combined with apply='restart' (resize first, then set maxRunMinutes).")
        }

        $body = [ordered]@{}
        if (-not [string]::IsNullOrWhiteSpace($Name)) { $body['name'] = Assert-InstaboxResourceName -Name $Name -Kind 'sandbox' }
        if ($PSBoundParameters.ContainsKey('Vcpus')) { $body['vcpus'] = $Vcpus }
        if ($PSBoundParameters.ContainsKey('MemMiB')) { $body['memMiB'] = $MemMiB }
        if ($PSBoundParameters.ContainsKey('PersistentDiskGiB')) { $body['persistentDiskGiB'] = $PersistentDiskGiB }
        if ($PSBoundParameters.ContainsKey('RootDiskGiB')) { $body['rootDiskGiB'] = $RootDiskGiB }
        if ($PSBoundParameters.ContainsKey('Metadata') -and $null -ne $Metadata) { $body['metadata'] = Assert-InstaboxMetadata -Metadata $Metadata }
        if ($PSBoundParameters.ContainsKey('AutoSuspendAfterSeconds')) { $body['autoSuspendAfterSeconds'] = $AutoSuspendAfterSeconds }
        if ($PSBoundParameters.ContainsKey('MaxRunMinutes')) { $body['maxRunMinutes'] = $MaxRunMinutes }
        if ($DisableVault) { $body['vault'] = $false }
        if ($CancelScheduled) { $body['cancelScheduled'] = $true }
        if (-not [string]::IsNullOrWhiteSpace($Apply)) { $body['apply'] = $Apply }

        $resp = Invoke-InstaboxRequest -Method 'PATCH' -Path "/v1/machines/$validId" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        if ($resp.StatusCode -eq 202 -and $Wait) {
            return (Wait-InstaboxOperation -Id $resp.Data.id)
        }
        return $resp.Data
    }
}

function Remove-InstaboxSandbox {
    <#
    .SYNOPSIS
    Deletes a sandbox, its system files, and its storage (DELETE /v1/machines/{id}).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$ConfirmName,

        [switch]$Now,

        [switch]$Force,

        [string]$IdempotencyKey,

        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $confirmHeader = $ConfirmName

        if ([string]::IsNullOrWhiteSpace($confirmHeader)) {
            if ($Force) {
                $confirmHeader = $validId
            }
            else {
                $machine = Get-InstaboxSandbox -Id $validId
                $expectedName = [string]$machine.name
                if ([Environment]::UserInteractive) {
                    $typed = Read-Host "Type sandbox name '$expectedName' (or '$validId') to confirm deletion"
                    if ($typed -ne $expectedName -and $typed -ne $validId) {
                        throw [System.OperationCanceledException]::new("Sandbox deletion aborted: confirmation text did not match '$expectedName'.")
                    }
                    $confirmHeader = $typed
                }
                else {
                    throw [System.InvalidOperationException]::new("Deleting sandbox '$validId' requires -ConfirmName or -Force in non-interactive sessions.")
                }
            }
        }

        if (-not $Force -and -not $PSCmdlet.ShouldProcess($validId, 'Delete sandbox and storage')) {
            return
        }

        $q = @{}
        if ($Now) { $q['now'] = $true }

        $resp = Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/machines/$validId" -Query $q -RequireIdempotency -IdempotencyKey $IdempotencyKey -ConfirmDelete $confirmHeader
        Remove-InstaboxSshHostBlock -MachineId $validId
        Clear-InstaboxKnownHostsEntry -MachineId $validId

        if ($Wait) {
            return (Wait-InstaboxOperation -Id $resp.Data.id)
        }
        return $resp.Data
    }
}

function Start-InstaboxSandbox {
    <#
    .SYNOPSIS
    Starts a stopped sandbox or resumes a paused one (POST /v1/machines/{id}/start).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [ValidateRange(1, 32)]
        [int]$Vcpus,
        [ValidateRange(512, 131072)]
        [int]$MemMiB,
        [switch]$Rescue,
        [switch]$AcceptMinimumLease,
        [switch]$DisableVault,
        [string]$TargetHost,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $body = [ordered]@{}
        if ($PSBoundParameters.ContainsKey('Vcpus')) { $body['vcpus'] = $Vcpus }
        if ($PSBoundParameters.ContainsKey('MemMiB')) { $body['memMiB'] = $MemMiB }
        if ($Rescue) { $body['rescue'] = $true }
        if ($AcceptMinimumLease) { $body['acceptMinimumLease'] = $true }
        if ($DisableVault) { $body['vault'] = $false }
        if (-not [string]::IsNullOrWhiteSpace($TargetHost)) { $body['host'] = $TargetHost }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/start" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        if ($Wait) { return (Wait-InstaboxOperation -Id $resp.Data.id) }
        return $resp.Data
    }
}

function Stop-InstaboxSandbox {
    <#
    .SYNOPSIS
    Stops a running sandbox (POST /v1/machines/{id}/stop).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [ValidateRange(0, 600)]
        [int]$TimeoutSeconds,
        [switch]$Now,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $body = [ordered]@{}
        $q = @{}
        if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $body['timeoutSeconds'] = $TimeoutSeconds }
        if ($Now) {
            $body['now'] = $true
            $q['now'] = $true
        }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/stop" -Query $q -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        if ($Wait) { return (Wait-InstaboxOperation -Id $resp.Data.id) }
        return $resp.Data
    }
}

function Suspend-InstaboxSandbox {
    <#
    .SYNOPSIS
    Pauses a running sandbox keeping its running programs (POST /v1/machines/{id}/suspend).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/suspend" -Body ([ordered]@{}) -RequireIdempotency -IdempotencyKey $IdempotencyKey
        if ($Wait) { return (Wait-InstaboxOperation -Id $resp.Data.id) }
        return $resp.Data
    }
}

function Resume-InstaboxSandbox {
    <#
    .SYNOPSIS
    Resumes a paused sandbox where it left off (POST /v1/machines/{id}/resume).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [switch]$DisableVault,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $body = [ordered]@{}
        if ($DisableVault) { $body['vault'] = $false }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/resume" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        if ($Wait) { return (Wait-InstaboxOperation -Id $resp.Data.id) }
        return $resp.Data
    }
}

function Invoke-InstaboxWake {
    <#
    .SYNOPSIS
    Resumes an idle-suspended sandbox synchronously or records activity (POST /v1/machines/{id}/wake).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/wake" -Body ([ordered]@{}) -TimeoutSeconds 75
        return $resp.Data
    }
}

function Copy-InstaboxSandbox {
    <#
    .SYNOPSIS
    Forks a running or stopped sandbox on its host without a snapshot (POST /v1/machines/{id}/fork).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$Name,
        [ValidateRange(1, 32)]
        [int]$Vcpus,
        [ValidateRange(512, 131072)]
        [int]$MemMiB,
        [hashtable]$Metadata,
        [ValidateRange(60, 86400)]
        [int]$DeleteAfterSeconds,
        [switch]$AcceptMinimumLease,
        [int]$AutoSuspendAfterSeconds,
        [ValidateRange(-1, 2147483647)]
        [int]$MaxRunMinutes,
        $ProxySecrets,
        [string[]]$EnvSecrets,
        [object[]]$DirectSecrets,
        [switch]$FallbackToSnapshot,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if ($PSBoundParameters.ContainsKey('EnvSecrets') -and $PSBoundParameters.ContainsKey('DirectSecrets')) {
            throw [System.ArgumentException]::new("-EnvSecrets and -DirectSecrets cannot be sent together.")
        }

        $body = [ordered]@{}
        if (-not [string]::IsNullOrWhiteSpace($Name)) { $body['name'] = Assert-InstaboxResourceName -Name $Name -Kind 'sandbox' }
        if ($PSBoundParameters.ContainsKey('Vcpus')) { $body['vcpus'] = $Vcpus }
        if ($PSBoundParameters.ContainsKey('MemMiB')) { $body['memMiB'] = $MemMiB }
        if ($PSBoundParameters.ContainsKey('Metadata') -and $null -ne $Metadata) { $body['metadata'] = Assert-InstaboxMetadata -Metadata $Metadata }
        if ($PSBoundParameters.ContainsKey('DeleteAfterSeconds')) { $body['deleteAfterSeconds'] = $DeleteAfterSeconds }
        if ($AcceptMinimumLease) { $body['acceptMinimumLease'] = $true }
        if ($PSBoundParameters.ContainsKey('AutoSuspendAfterSeconds')) { $body['autoSuspendAfterSeconds'] = $AutoSuspendAfterSeconds }
        if ($PSBoundParameters.ContainsKey('MaxRunMinutes')) { $body['maxRunMinutes'] = $MaxRunMinutes }

        if ($PSBoundParameters.ContainsKey('ProxySecrets') -and $null -ne $ProxySecrets) {
            if ($ProxySecrets -is [string] -and $ProxySecrets -eq 'all') {
                $body['secrets'] = 'all'
            }
            else {
                $body['secrets'] = [string[]]@($ProxySecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
            }
        }
        if ($PSBoundParameters.ContainsKey('EnvSecrets') -and $null -ne $EnvSecrets) {
            $body['envSecrets'] = [string[]]@($EnvSecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
        }
        if ($PSBoundParameters.ContainsKey('DirectSecrets') -and $null -ne $DirectSecrets) {
            $body['directSecrets'] = @($DirectSecrets)
        }

        try {
            $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/fork" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
            $op = $resp.Data
            if ($Wait) { return (Wait-InstaboxOperation -Id $op.id) }
            return $op
        }
        catch [Instabox.InstaboxApiException] {
            $ex = $_.Exception
            if ($FallbackToSnapshot -and $ex.Code -eq 'fork_unavailable') {
                Write-Warning "Host fork unavailable ($($ex.Message)); falling back to snapshot (forFork=true) + create."
                $snapName = "fork-$(([guid]::NewGuid().ToString('N')).Substring(0, 8))"
                $snap = New-InstaboxSnapshot -SandboxId $validId -Name $snapName -ForFork -Wait
                $createArgs = @{ SnapshotId = $snap.id; Wait = $Wait }
                if (-not [string]::IsNullOrWhiteSpace($Name)) { $createArgs['Name'] = $Name }
                if ($PSBoundParameters.ContainsKey('Vcpus')) { $createArgs['Vcpus'] = $Vcpus }
                if ($PSBoundParameters.ContainsKey('MemMiB')) { $createArgs['MemMiB'] = $MemMiB }
                if ($PSBoundParameters.ContainsKey('Metadata') -and $null -ne $Metadata) { $createArgs['Metadata'] = $Metadata }
                return (New-InstaboxSandbox @createArgs)
            }
            throw
        }
    }
}

function Restore-InstaboxSandbox {
    <#
    .SYNOPSIS
    Restores a sandbox's disks in place from a snapshot (POST /v1/machines/{id}/restore).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [string]$SnapshotId,
        [ValidateSet('running', 'stopped')]
        [string]$DesiredState,
        [ValidateRange(0, 600)]
        [int]$TimeoutSeconds,
        [switch]$AcceptMinimumLease,
        [switch]$Force,
        [string]$IdempotencyKey,
        [switch]$Wait
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if (-not $Force -and -not $PSCmdlet.ShouldProcess($validId, 'Restore sandbox disks from snapshot (overwrites all disk changes and regenerates SSH host keys)')) {
            return
        }

        $body = [ordered]@{}
        if (-not [string]::IsNullOrWhiteSpace($SnapshotId)) { $body['snapshotId'] = Assert-InstaboxSnapshotId -Id $SnapshotId }
        if (-not [string]::IsNullOrWhiteSpace($DesiredState)) { $body['desiredState'] = $DesiredState }
        if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $body['timeoutSeconds'] = $TimeoutSeconds }
        if ($AcceptMinimumLease) { $body['acceptMinimumLease'] = $true }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/restore" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        # Restoring regenerates SSH host keys on the guest
        Clear-InstaboxKnownHostsEntry -MachineId $validId

        if ($Wait) { return (Wait-InstaboxOperation -Id $resp.Data.id) }
        return $resp.Data
    }
}
